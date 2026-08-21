# PrivacyTrace-NP — End-to-end API smoke test (through Phase 10)
# Requires: backend running at http://127.0.0.1:8000
# Run from project root: .\scripts\demo_smoke_test.ps1
$ErrorActionPreference = "Stop"

$BaseUrl = if ($env:PRIVACYTRACE_BASE_URL) { $env:PRIVACYTRACE_BASE_URL } else { "http://127.0.0.1:8000" }
$IncidentId = "INC-SEED-001"
$AuthEmail = if ($env:PRIVACYTRACE_TEST_EMAIL) { $env:PRIVACYTRACE_TEST_EMAIL } else { "analyst@privacytrace.local" }
$AuthPassword = if ($env:PRIVACYTRACE_TEST_PASSWORD) { $env:PRIVACYTRACE_TEST_PASSWORD } else { "AnalystPass123!" }
$script:AuthHeaders = @{}

$RawLeakPatterns = @(
    "9841234567",
    "WALLET-NP-88291",
    "pk_test_np_fake_12345",
    "SYNTHETIC_FAKE_PAYLOAD.NOT_A_REAL_TOKEN",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    "Bearer eyJ"
)

$OverclaimPhrases = @(
    "proven cause",
    "confirmed blame",
    "guaranteed cause",
    "definitely caused by",
    "developer fault",
    "incident closed automatically",
    "guaranteed fixed",
    "definitely fixed",
    "proven fixed"
)

$script:PassCount = 0
$script:FailCount = 0
$script:AllResponseText = ""

function Write-StepResult([string]$StepName, [bool]$Ok, [string]$Endpoint, [string]$Summary) {
    $label = if ($Ok) { "PASS" } else { "FAIL" }
    $color = if ($Ok) { "Green" } else { "Red" }
    if ($Ok) { $script:PassCount++ } else { $script:FailCount++ }
    Write-Host ""
    Write-Host "[$label] $StepName" -ForegroundColor $color
    Write-Host "  Endpoint: $Endpoint"
    Write-Host "  Summary:  $Summary"
}

function Get-SafeJsonSummary($obj) {
    if ($null -eq $obj) { return "(empty)" }
    try {
        $json = $obj | ConvertTo-Json -Depth 8 -Compress
        if ($json.Length -gt 400) { return $json.Substring(0, 400) + "..." }
        return $json
    } catch {
        return "(non-JSON response)"
    }
}

function Add-ResponseText($obj) {
    try {
        $script:AllResponseText += ($obj | ConvertTo-Json -Depth 20)
    } catch {
        $script:AllResponseText += [string]$obj
    }
}

function Test-NoRawLeaks([string]$Blob) {
    foreach ($p in $RawLeakPatterns) {
        if ($Blob -like "*$p*") { return $false }
    }
    if ($Blob -match '(?i)authorization\s*:\s*bearer\s+eyJ') { return $false }
    return $true
}

function Get-OverclaimScanBlob([string]$Blob) {
    $scrubbed = [regex]::Replace($Blob, '"validation_errors"\s*:\s*\[[^\]]*\]', '"validation_errors":[]')
    # Allowed negations used by template/trace disclaimer (not overclaims).
    $scrubbed = [regex]::Replace($scrubbed, '(?i)not confirmed blame', 'NEGATED_BLAME')
    $scrubbed = [regex]::Replace($scrubbed, '(?i)not proven cause', 'NEGATED_PROVEN')
    $scrubbed = [regex]::Replace($scrubbed, '(?i)must not claim definite proof or confirmed blame', 'NEGATED_PROMPT')
    return $scrubbed
}

function Test-NoOverclaims([string]$Blob) {
    $lower = (Get-OverclaimScanBlob $Blob).ToLowerInvariant()
    foreach ($phrase in $OverclaimPhrases) {
        if ($lower.Contains($phrase)) { return $false }
    }
    return $true
}

function Test-HasEvidenceIds([string]$Blob) {
    return $Blob -match 'EVD-S1-[A-Z0-9-]+'
}

function Test-LikelyCauseWording([string]$Blob) {
    return ($Blob -match '(?i)likely')
}

function Invoke-ApiStep {
    param(
        [string]$StepName,
        [string]$Method,
        [string]$Path,
        [object]$Body = $null,
        [scriptblock]$Validator
    )
    $uri = "$BaseUrl$Path"
    try {
        if ($Method -eq "GET") {
            $resp = Invoke-RestMethod -Uri $uri -Method Get -Headers $script:AuthHeaders -TimeoutSec 120
        } else {
            $jsonBody = if ($null -ne $Body) { $Body | ConvertTo-Json -Compress } else { "{}" }
            $resp = Invoke-RestMethod -Uri $uri -Method Post -Headers $script:AuthHeaders -ContentType "application/json" -Body $jsonBody -TimeoutSec 120
        }
        Add-ResponseText $resp
        $ok = & $Validator $resp
        $summary = Get-SafeJsonSummary $resp
        Write-StepResult -StepName $StepName -Ok $ok -Endpoint "$Method $Path" -Summary $summary
        return $resp
    } catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
        Write-StepResult -StepName $StepName -Ok $false -Endpoint "$Method $Path" -Summary "HTTP/error: $msg"
        return $null
    }
}

Write-Host "PrivacyTrace-NP smoke test" -ForegroundColor Cyan
Write-Host "Base URL: $BaseUrl"

# Pre-check backend
try {
    $null = Invoke-WebRequest -Uri "$BaseUrl/health" -UseBasicParsing -TimeoutSec 5
} catch {
    Write-Host ""
    Write-Host "FAILED: Backend not reachable at $BaseUrl" -ForegroundColor Red
    Write-Host "Start: cd backend; uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"
    exit 1
}

try {
    $loginBody = @{ email = $AuthEmail; password = $AuthPassword } | ConvertTo-Json -Compress
    $login = Invoke-RestMethod -Uri "$BaseUrl/auth/login" -Method Post -ContentType "application/json" -Body $loginBody -TimeoutSec 30
    if (-not $login.access_token) { throw "Authentication response did not include access_token." }
    $script:AuthHeaders = @{ Authorization = "Bearer $($login.access_token)" }
} catch {
    Write-Host ""
    Write-Host "FAILED: Authentication failed for $AuthEmail. Run the auth-user seed and verify test credentials." -ForegroundColor Red
    exit 1
}

Invoke-ApiStep -StepName "Health check" -Method "GET" -Path "/health" -Validator {
    param($r)
    ($r.status -in @("ok", "healthy")) -and ($r.database -eq "connected")
}

Invoke-ApiStep -StepName "Load sample evidence" -Method "POST" -Path "/evidence/load-sample" -Body @{ scenario = "scenario_1" } -Validator {
    param($r)
    if ($null -eq $r) { return $false }
    if ($r.loaded.Count -gt 0) { return $true }
    if ($r.evidence_ids.Count -gt 0) { return $true }
    # Idempotent re-run: files already ingested from a prior pass in the same DB session.
    return ($r.scenario -eq "scenario_1") -and ($r.skipped.Count -gt 0)
}

Invoke-ApiStep -StepName "Parse all evidence" -Method "POST" -Path "/evidence/parse-all" -Validator {
    param($r) $null -ne $r
}

Invoke-ApiStep -StepName "Detect and mask all" -Method "POST" -Path "/evidence/detect-all" -Validator {
    param($r) $null -ne $r
}

Invoke-ApiStep -StepName "Analyse incident (rank causes)" -Method "POST" -Path "/incidents/analyse" -Body @{ incident_id = $IncidentId } -Validator {
    param($r)
    if ($null -eq $r) { return $false }
    foreach ($item in $r.results) {
        if ($item.incident_id -eq $IncidentId) {
            return ($item.top_likely_cause -eq "unsafe_request_body_logging") -and ($item.status -eq "analysed")
        }
    }
    return $false
}

$trace = Invoke-ApiStep -StepName "Retrieve incident trace" -Method "GET" -Path "/incidents/$IncidentId/trace" -Validator {
    param($r)
    if ($null -eq $r) { return $false }
    $causes = $r.likely_root_causes
    if ($causes -and $causes.Count -gt 0) {
        return $causes[0].likely_root_cause -eq "unsafe_request_body_logging"
    }
    return $true
}

Invoke-ApiStep -StepName "Guarded LLM explanation" -Method "POST" -Path "/incidents/$IncidentId/explain" -Body @{ provider = "template" } -Validator {
    param($r)
    if ($null -eq $r) { return $false }
    $out = $r.output
    if (-not $out) { $out = $r }
    $required = @("incident_summary", "likely_cause_explanation", "supporting_evidence_summary", "alternative_hypotheses", "missing_evidence_questions", "recommended_fix_draft", "fix_verification_checklist", "human_review_note")
    foreach ($k in $required) {
        if (-not ($out.PSObject.Properties.Name -contains $k)) { return $false }
    }
    return $true
}

Invoke-ApiStep -StepName "Retrieve LLM reports" -Method "GET" -Path "/incidents/$IncidentId/llm-reports" -Validator {
    param($r)
    if ($null -eq $r) { return $false }
    $reports = $r.reports
    if (-not $reports) { $reports = $r }
    if ($reports -is [System.Array]) { return $reports.Count -gt 0 }
    return $true
}

Invoke-ApiStep -StepName "Human review (approved)" -Method "POST" -Path "/incidents/$IncidentId/review" -Body @{
    decision = "approved"
    comment  = "Supporting evidence reviewed; likely unsafe request-body logging. Human review required before closure."
} -Validator {
    param($r)
    if ($null -eq $r) { return $false }
    return ($r.incident_status -eq "confirmed_incident") -and ($r.review.decision -eq "approved")
}

Invoke-ApiStep -StepName "Record remediation action" -Method "POST" -Path "/incidents/$IncidentId/remediation-actions" -Body @{
    action_type        = "redaction_rule_update"
    action_description = "Update the reviewed wallet logging redaction rule."
    affected_component = "wallet logging middleware"
    assigned_owner     = "wallet platform team"
    status             = "awaiting_retest"
    priority           = "high"
    retest_required    = $true
} -Validator {
    param($r) $null -ne $r
}

$retestEvidenceId = $null
try {
    $sampleRetest = Join-Path $PSScriptRoot "..\backend\app\sample_data\retest_evidence\wallet_transfer_retest.log"
    if (-not (Test-Path $sampleRetest)) {
        throw "Safe retest sample not found: $sampleRetest"
    }
    $uniqueRetest = [System.IO.Path]::GetTempFileName() + ".log"
    $baseContent = Get-Content -Path $sampleRetest -Raw -Encoding UTF8
    $runTag = [Guid]::NewGuid().ToString("n").Substring(0, 8)
    Set-Content -Path $uniqueRetest -Value ($baseContent + "`n# smoke-run $runTag`n") -Encoding UTF8 -NoNewline
    $uploadUri = "$BaseUrl/evidence/upload"
    $form = @{
        file               = Get-Item -LiteralPath $uniqueRetest
        evidence_type      = "fixed_log"
        linked_incident_id = $IncidentId
    }
    $uploadResp = Invoke-RestMethod -Uri $uploadUri -Method Post -Headers $script:AuthHeaders -Form $form -TimeoutSec 120
    Add-ResponseText $uploadResp
    $retestEvidenceId = $uploadResp.evidence_id
    if (-not $retestEvidenceId) { $retestEvidenceId = $uploadResp.evidence.evidence_id }
    Write-StepResult -StepName "Upload safe retest evidence" -Ok ($null -ne $retestEvidenceId) -Endpoint "POST /evidence/upload" -Summary (Get-SafeJsonSummary $uploadResp)
} catch {
    Write-StepResult -StepName "Upload safe retest evidence" -Ok $false -Endpoint "POST /evidence/upload" -Summary $_.Exception.Message
} finally {
    if ($uniqueRetest -and (Test-Path $uniqueRetest)) { Remove-Item -LiteralPath $uniqueRetest -Force -ErrorAction SilentlyContinue }
}

$verifyBody = @{}
if ($retestEvidenceId) { $verifyBody["retest_evidence_ids"] = @($retestEvidenceId) }

Invoke-ApiStep -StepName "Fix verification (Phase 9)" -Method "POST" -Path "/incidents/$IncidentId/verify-fix" -Body $verifyBody -Validator {
    param($r)
    if ($null -eq $r) { return $false }
    $statusOk = $r.verification_status -in @("passed", "failed", "inconclusive")
    $humanOk = $r.human_review_required -eq $true
    $checksOk = ($r.checks_run -contains "phase_8_gate_check")
    return $statusOk -and $humanOk -and $checksOk
}

Invoke-ApiStep -StepName "List fix verifications" -Method "GET" -Path "/incidents/$IncidentId/fix-verifications" -Validator {
    param($r)
    if ($null -eq $r) { return $false }
    $items = $r.verifications
    if (-not $items) { $items = $r }
    if ($items -is [System.Array]) { return $items.Count -gt 0 }
    return $true
}

Invoke-ApiStep -StepName "Generate JSON incident report (Phase 10)" -Method "POST" -Path "/reports/incidents/$IncidentId/generate" -Body @{
    report_type = "json"
} -Validator {
    param($r)
    if ($null -eq $r) { return $false }
    return ($null -ne $r.report_id) -and ($null -ne $r.content)
}

Invoke-ApiStep -StepName "Generate HTML incident report (Phase 10)" -Method "POST" -Path "/reports/incidents/$IncidentId/generate" -Body @{
    report_type = "html"
} -Validator {
    param($r)
    if ($null -eq $r) { return $false }
    return ($null -ne $r.html_document) -and ($r.html_document.Length -gt 50)
}

Invoke-ApiStep -StepName "Run evaluation metrics (Phase 10)" -Method "POST" -Path "/metrics/evaluation/run" -Body @{} -Validator {
    param($r) $null -ne $r
}

Invoke-ApiStep -StepName "List evaluation metrics (Phase 10)" -Method "GET" -Path "/metrics/evaluation" -Validator {
    param($r)
    if ($null -eq $r) { return $false }
    $metrics = $r.metrics
    if (-not $metrics) { $metrics = $r }
    if ($metrics -is [System.Array]) {
        if ($metrics.Count -lt 1) { return $false }
        $first = $metrics[0]
        return ($null -ne $first.thesis_claim) -and ($null -ne $first.calculation_method)
    }
    return $true
}

# Global safety checks on accumulated JSON
Write-Host ""
Write-Host "==> Global safety checks" -ForegroundColor Cyan

$leakOk = Test-NoRawLeaks $script:AllResponseText
Write-StepResult -StepName "No raw sensitive values in responses" -Ok $leakOk -Endpoint "(all steps)" -Summary $(if ($leakOk) { "No forbidden substrings found" } else { "Forbidden raw pattern detected in combined JSON" })

$overclaimOk = Test-NoOverclaims $script:AllResponseText
Write-StepResult -StepName "No overclaim phrases" -Ok $overclaimOk -Endpoint "(all steps)" -Summary $(if ($overclaimOk) { "No standalone overclaim phrases" } else { "Overclaim phrase detected" })

$evidenceOk = Test-HasEvidenceIds $script:AllResponseText
Write-StepResult -StepName "Evidence IDs present" -Ok $evidenceOk -Endpoint "(all steps)" -Summary $(if ($evidenceOk) { "EVD-S1-* found" } else { "No EVD-S1 evidence IDs in responses" })

$likelyOk = Test-LikelyCauseWording $script:AllResponseText
Write-StepResult -StepName "Likely-cause wording present" -Ok $likelyOk -Endpoint "(all steps)" -Summary $(if ($likelyOk) { "Contains likely-cause language" } else { "Missing likely wording" })

Write-Host ""
if ($script:FailCount -eq 0) {
    Write-Host "SMOKE TEST: PASS ($($script:PassCount) checks)" -ForegroundColor Green
    exit 0
} else {
    Write-Host "SMOKE TEST: FAIL ($($script:PassCount) passed, $($script:FailCount) failed)" -ForegroundColor Red
    exit 1
}
