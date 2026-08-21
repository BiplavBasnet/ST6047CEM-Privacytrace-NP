# PrivacyTrace-NP - Prepare full workflow state for Phase 10 reports/metrics
# Requires: docker compose up, alembic upgrade head, seed, uvicorn on port 8000
# Run from project root: .\scripts\phase10_prepare_workflow.ps1
$ErrorActionPreference = "Stop"

. "$PSScriptRoot\phase10_common.ps1"
Initialize-Phase10EvidenceDirs

$script:StepResults = @()
$script:Failed = $false

function Write-WorkflowStep {
    param(
        [string]$Name,
        [bool]$Ok,
        [string]$Detail = ""
    )
    $label = if ($Ok) { "PASS" } else { "FAIL" }
    $color = if ($Ok) { "Green" } else { "Red" }
    if (-not $Ok) { $script:Failed = $true }
    $script:StepResults += @{ name = $Name; pass = $Ok; detail = $Detail }
    Write-Phase10Line "[$label] $Name" $color
    if ($Detail) { Write-Phase10Line "       $Detail" "Gray" }
    if (-not $Ok) { throw "Workflow step failed: $Name. $Detail" }
}

Write-Phase10Line "PrivacyTrace-NP Phase 10 workflow preparation" "Cyan"
Write-Phase10Line "Base URL: $($script:Phase10BaseUrl)" "Gray"

try {
    $health = Assert-Phase10HealthReady
    Save-Phase10SafeJson -Name "01_health.json" -Object $health | Out-Null
    Write-WorkflowStep -Name "GET /health" -Ok $true -Detail "database connected"

    $load = Invoke-Phase10Api -Method POST -Path "/evidence/load-sample" -Body @{ scenario = "scenario_1" }
    Save-Phase10SafeJson -Name "02_load_sample.json" -Object $load | Out-Null
    Write-WorkflowStep -Name "POST /evidence/load-sample" -Ok $true

    $parse = Invoke-Phase10Api -Method POST -Path "/evidence/parse-all"
    Save-Phase10SafeJson -Name "03_parse_all.json" -Object $parse | Out-Null
    Write-WorkflowStep -Name "POST /evidence/parse-all" -Ok $true

    $detect = Invoke-Phase10Api -Method POST -Path "/evidence/detect-all"
    Save-Phase10SafeJson -Name "04_detect_all.json" -Object $detect | Out-Null
    Write-WorkflowStep -Name "POST /evidence/detect-all" -Ok $true

    $analyse = Invoke-Phase10Api -Method POST -Path "/incidents/analyse" -Body @{ incident_id = $script:Phase10IncidentId }
    Save-Phase10SafeJson -Name "05_analyse.json" -Object $analyse | Out-Null
    $topOk = $false
    foreach ($item in $analyse.results) {
        if ($item.incident_id -eq $script:Phase10IncidentId -and $item.top_likely_cause) {
            $topOk = $true
            break
        }
    }
    Write-WorkflowStep -Name "POST /incidents/analyse" -Ok $topOk -Detail "root-cause ranking present"

    $trace = Invoke-Phase10Api -Method GET -Path "/incidents/$($script:Phase10IncidentId)/trace"
    Save-Phase10SafeJson -Name "06_incident_trace.json" -Object $trace | Out-Null
    $traceBlob = $trace | ConvertTo-Json -Depth 25
    $hasCauses = ($trace.likely_root_causes -and $trace.likely_root_causes.Count -gt 0)
    Write-WorkflowStep -Name "GET /incidents/{id}/trace" -Ok $hasCauses

    $explain = Invoke-Phase10Api -Method POST -Path "/incidents/$($script:Phase10IncidentId)/explain" -Body @{ provider = "template" }
    Save-Phase10SafeJson -Name "07_explain.json" -Object $explain | Out-Null
    $explainBlob = $explain | ConvertTo-Json -Depth 25
    $hasExplain = ($explain.output -or $explain.report_id)
    Write-WorkflowStep -Name "POST /incidents/{id}/explain" -Ok $hasExplain

    $review = Invoke-Phase10Api -Method POST -Path "/incidents/$($script:Phase10IncidentId)/review" -Body @{
        decision = "approved"
        comment  = "Supporting evidence reviewed; likely unsafe request-body logging. Human review required before closure."
    }
    Save-Phase10SafeJson -Name "08_review.json" -Object $review | Out-Null
    $reviewOk = ($review.incident_status -eq "confirmed_incident") -and ($review.review.decision -eq "approved")
    Write-WorkflowStep -Name "POST /incidents/{id}/review (approved)" -Ok $reviewOk

    $remediation = Invoke-Phase10Api -Method POST -Path "/incidents/$($script:Phase10IncidentId)/remediation-actions" -Body @{
        action_type          = "redaction_rule_update"
        action_description   = "Update the reviewed wallet logging redaction rule."
        affected_component   = "wallet logging middleware"
        assigned_owner       = "wallet platform team"
        status               = "awaiting_retest"
        priority             = "high"
        retest_required      = $true
    }
    Save-Phase10SafeJson -Name "08b_remediation_action.json" -Object $remediation | Out-Null
    Write-WorkflowStep -Name "POST /incidents/{id}/remediation-actions" -Ok ($null -ne $remediation)

    $retestId = Upload-Phase10SafeRetestEvidence
    $verify = Invoke-Phase10Api -Method POST -Path "/incidents/$($script:Phase10IncidentId)/verify-fix" -Body @{
        retest_evidence_ids = @($retestId)
    }
    Save-Phase10SafeJson -Name "09_verify_fix.json" -Object $verify | Out-Null
    $verifyOk = $verify.verification_status -in @("passed", "failed", "inconclusive")
    Write-WorkflowStep -Name "POST /incidents/{id}/verify-fix" -Ok $verifyOk -Detail "status=$($verify.verification_status)"

    # Workflow prerequisite checks on accumulated safe outputs
    $allBlob = ""
    Get-ChildItem -Path $script:Phase10ApiOutDir -Filter "*.json" | ForEach-Object {
        $allBlob += Get-Content -Path $_.FullName -Raw -Encoding UTF8
    }
    Write-WorkflowStep -Name "Evidence IDs present in outputs" -Ok (Test-Phase10BlobHasEvidenceIds $allBlob)
    Write-WorkflowStep -Name "Likely-cause wording present" -Ok (Test-Phase10BlobHasLikelyWording $allBlob)
    $overclaimCheck = Test-Phase10SafeContent -Label "workflow_outputs" -Blob $allBlob
    Write-WorkflowStep -Name "No overclaim phrases in outputs" -Ok $overclaimCheck.Ok -Detail ($overclaimCheck.Violations -join "; ")

    Write-Phase10Line "" "White"
    Write-Phase10Line "PHASE 10 WORKFLOW PREPARATION: PASS" "Green"
    exit 0
} catch {
    Write-Phase10Line "" "White"
    Write-Phase10Line "PHASE 10 WORKFLOW PREPARATION: FAIL" "Red"
    Write-Phase10Line $_.Exception.Message "Red"
    exit 1
}
