# PrivacyTrace-NP - Phase 10 thesis evidence capture (strict PASS/FAIL)
# Run from project root: .\scripts\capture_phase10_evidence.ps1
$ErrorActionPreference = "Stop"

. "$PSScriptRoot\phase10_common.ps1"
Initialize-Phase10EvidenceDirs

$script:CaptureResults = @{
    timestamp                    = (Get-Date -Format o)
    pytest                       = "not_run"
    health                       = "not_run"
    workflow_preparation         = "not_run"
    report_json                  = "not_run"
    report_html                  = "not_run"
    metrics                      = "not_run"
    raw_sensitive_scan           = "not_run"
    overclaim_scan               = "not_run"
    evidence_ids_in_reports      = "not_run"
    metrics_thesis_fields        = "not_run"
    final                        = "FAIL"
}
$script:FailureReasons = @()

function Add-CaptureFailure([string]$Reason) {
    if ($script:FailureReasons -notcontains $Reason) {
        $script:FailureReasons += $Reason
    }
}

function Set-CaptureResult([string]$Key, [string]$Value) {
    $script:CaptureResults[$Key] = $Value
}

function Write-CaptureBanner([string]$Msg, [string]$Color = "Cyan") {
    Write-Phase10Line $Msg $Color
}

function Assert-CaptureStep {
    param(
        [string]$Key,
        [string]$PassValue,
        [scriptblock]$Action
    )
    try {
        & $Action
        Set-CaptureResult -Key $Key -Value $PassValue
        return $true
    } catch {
        Set-CaptureResult -Key $Key -Value "FAIL"
        Add-CaptureFailure "$Key : $($_.Exception.Message)"
        throw
    }
}

Write-CaptureBanner "PrivacyTrace-NP Phase 10 evidence capture"
Write-CaptureBanner "Evidence dir: $($script:Phase10EvidenceDir)" "Gray"

try {
    # 1) pytest
    Assert-CaptureStep -Key "pytest" -PassValue "PASS" -Action {
        $testOut = Join-Path $script:Phase10EvidenceDir "test_results.txt"
        $runner = Join-Path $script:Phase10ProjectRoot "scripts\run_backend_tests_with_postgres.py"
        $python = Join-Path $script:Phase10BackendDir ".venv\Scripts\python.exe"
        if (-not (Test-Path $python)) { throw "Python venv not found at $python" }
        if (-not (Test-Path $runner)) { throw "Isolated PostgreSQL test runner not found at $runner" }
        Push-Location $script:Phase10ProjectRoot
        try {
            & $python $runner -v 2>&1 | Tee-Object -FilePath $testOut
            if ($LASTEXITCODE -ne 0) { throw "isolated backend test runner exited with code $LASTEXITCODE" }
        } finally {
            Pop-Location
        }
        $txt = Get-Content -Path $testOut -Raw -Encoding UTF8
        $check = Test-Phase10SafeContent -Label "test_results.txt" -Blob $txt -SkipRawScan
        if (-not $check.Ok) { throw ($check.Violations -join "; ") }
        Write-Phase10Line "[PASS] isolated Phase 8-10 PostgreSQL tests" "Green"
    }

    # 2) health (fail if backend down or DB disconnected)
    Assert-CaptureStep -Key "health" -PassValue "PASS" -Action {
        $healthBody = Assert-Phase10HealthReady
        Save-Phase10SafeJson -Name "capture_health.json" -Object $healthBody | Out-Null
        Write-Phase10Line "[PASS] GET /health (status healthy, database connected)" "Green"
    }

    # 3) workflow preparation via dedicated script
    Assert-CaptureStep -Key "workflow_preparation" -PassValue "PASS" -Action {
        $prepScript = Join-Path $PSScriptRoot "phase10_prepare_workflow.ps1"
        if (-not (Test-Path $prepScript)) { throw "Missing $prepScript" }
        & powershell -NoProfile -ExecutionPolicy Bypass -File $prepScript
        if ($LASTEXITCODE -ne 0) { throw "phase10_prepare_workflow.ps1 exited with code $LASTEXITCODE" }
        Write-Phase10Line "[PASS] phase10_prepare_workflow.ps1" "Green"
    }

    # 4) JSON report
    Assert-CaptureStep -Key "report_json" -PassValue "PASS" -Action {
        $r = Invoke-Phase10Api -Method POST -Path "/reports/incidents/$($script:Phase10IncidentId)/generate" -Body @{
            report_type = "json"
        }
        Save-Phase10SafeJson -Name "report_json_generate.json" -Object $r | Out-Null
        $blob = $r | ConvertTo-Json -Depth 30
        if (-not (Test-Phase10BlobHasEvidenceIds $blob)) { throw "JSON report missing evidence IDs" }
        Write-Phase10Line "[PASS] POST generate JSON report" "Green"
    }

    # 5) HTML report
    Assert-CaptureStep -Key "report_html" -PassValue "PASS" -Action {
        $r = Invoke-Phase10Api -Method POST -Path "/reports/incidents/$($script:Phase10IncidentId)/generate" -Body @{
            report_type = "html"
        }
        $meta = @{
            report_id    = $r.report_id
            incident_id  = $r.incident_id
            report_type  = $r.report_type
            created_at   = $r.created_at
            html_length  = if ($r.html_document) { $r.html_document.Length } else { 0 }
            content_keys = if ($r.content) { @($r.content.PSObject.Properties.Name) } else { @() }
        }
        Save-Phase10SafeJson -Name "report_html_generate_meta.json" -Object $meta | Out-Null
        if ($r.html_document) {
            Save-Phase10SafeHtml -Name "report_html_document.html" -Html $r.html_document | Out-Null
        }
        $blob = ($r | ConvertTo-Json -Depth 30)
        if ($r.html_document) { $blob += $r.html_document }
        if (-not (Test-Phase10BlobHasEvidenceIds $blob)) { throw "HTML report missing evidence IDs" }
        Write-Phase10Line "[PASS] POST generate HTML report" "Green"
    }

    # 6) metrics
    Assert-CaptureStep -Key "metrics" -PassValue "PASS" -Action {
        Invoke-Phase10Api -Method POST -Path "/metrics/evaluation/run" -Body @{} | Out-Null
        $m = Invoke-Phase10Api -Method GET -Path "/metrics/evaluation"
        Save-Phase10SafeJson -Name "evaluation_metrics.json" -Object $m | Out-Null
        Write-Phase10Line "[PASS] POST /metrics/evaluation/run + GET /metrics/evaluation" "Green"
    }

    # 7) evidence IDs in report outputs
    Assert-CaptureStep -Key "evidence_ids_in_reports" -PassValue "PASS" -Action {
        $reportBlob = ""
        foreach ($name in @("report_json_generate.json", "report_html_generate_meta.json", "report_html_document.html")) {
            $p = Join-Path $script:Phase10ApiOutDir $name
            if (Test-Path $p) { $reportBlob += Get-Content -Path $p -Raw -Encoding UTF8 }
        }
        if (-not (Test-Phase10BlobHasEvidenceIds $reportBlob)) {
            throw "Evidence IDs (EVD-S1-*) not found in saved report outputs"
        }
        Write-Phase10Line "[PASS] Evidence IDs present in report outputs" "Green"
    }

    # 8) metrics thesis fields
    Assert-CaptureStep -Key "metrics_thesis_fields" -PassValue "PASS" -Action {
        $metricsPath = Join-Path $script:Phase10ApiOutDir "evaluation_metrics.json"
        if (-not (Test-Path $metricsPath)) { throw "evaluation_metrics.json missing" }
        $metrics = Get-Content -Path $metricsPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $items = if ($metrics.metrics) { $metrics.metrics } elseif ($metrics -is [System.Array]) { $metrics } else { @() }
        if ($items.Count -eq 0) { throw "No metrics returned" }
        foreach ($metric in $items) {
            $name = if ($metric.metric_name) { $metric.metric_name } else { $metric.name }
            if ($script:Phase10RequiredMetrics -contains $name) {
                if (-not $metric.thesis_claim) { throw "Metric '$name' missing thesis_claim" }
                if (-not $metric.calculation_method) { throw "Metric '$name' missing calculation_method" }
            }
        }
        foreach ($required in $script:Phase10RequiredMetrics) {
            $found = $false
            foreach ($metric in $items) {
                $n = if ($metric.metric_name) { $metric.metric_name } else { $metric.name }
                if ($n -eq $required) { $found = $true; break }
            }
            if (-not $found) { throw "Required metric missing: $required" }
        }
        Write-Phase10Line "[PASS] Metrics include thesis_claim and calculation_method" "Green"
    }

    # 9-10) scans
    $scanFailures = Scan-Phase10AllApiOutputs
    if ($scanFailures.Count -eq 0) {
        Set-CaptureResult -Key "raw_sensitive_scan" -Value "PASS"
        Set-CaptureResult -Key "overclaim_scan" -Value "PASS"
        Write-Phase10Line "[PASS] Raw sensitive value scan (api_outputs)" "Green"
        Write-Phase10Line "[PASS] Overclaim phrase scan (api_outputs)" "Green"
    } else {
        Set-CaptureResult -Key "raw_sensitive_scan" -Value "FAIL"
        Set-CaptureResult -Key "overclaim_scan" -Value "FAIL"
        foreach ($f in $scanFailures) { Add-CaptureFailure "scan: $f" }
        throw "Safety scan failed: $($scanFailures -join '; ')"
    }

    Set-CaptureResult -Key "final" -Value "PASS"
} catch {
    if ($script:CaptureResults.final -ne "PASS") {
        Set-CaptureResult -Key "final" -Value "FAIL"
    }
}

# Write capture_summary.json
$summaryJson = @{
    timestamp = $script:CaptureResults.timestamp
    results   = $script:CaptureResults
    failures  = $script:FailureReasons
    pass      = ($script:CaptureResults.final -eq "PASS")
}
$summaryJsonPath = Join-Path $script:Phase10EvidenceDir "capture_summary.json"
$summaryJson | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryJsonPath -Encoding UTF8

# Legacy text summary
$summaryTxt = @"
Phase 10 evidence capture
Timestamp: $($script:CaptureResults.timestamp)
Result: $($script:CaptureResults.final)
pytest: $($script:CaptureResults.pytest)
health: $($script:CaptureResults.health)
workflow_preparation: $($script:CaptureResults.workflow_preparation)
report_json: $($script:CaptureResults.report_json)
report_html: $($script:CaptureResults.report_html)
metrics: $($script:CaptureResults.metrics)
raw_sensitive_scan: $($script:CaptureResults.raw_sensitive_scan)
overclaim_scan: $($script:CaptureResults.overclaim_scan)
evidence_ids_in_reports: $($script:CaptureResults.evidence_ids_in_reports)
metrics_thesis_fields: $($script:CaptureResults.metrics_thesis_fields)
"@
if ($script:FailureReasons.Count -gt 0) {
    $summaryTxt += "`n`nFailures:`n" + ($script:FailureReasons -join "`n")
}
Set-Content -Path (Join-Path $script:Phase10EvidenceDir "capture_summary.txt") -Value $summaryTxt -Encoding UTF8

# capture_status.md
$statusMd = @"
# Phase 10 evidence capture status

| Check | Result |
|-------|--------|
| Timestamp | $($script:CaptureResults.timestamp) |
| pytest | $($script:CaptureResults.pytest) |
| health | $($script:CaptureResults.health) |
| workflow preparation | $($script:CaptureResults.workflow_preparation) |
| report JSON | $($script:CaptureResults.report_json) |
| report HTML | $($script:CaptureResults.report_html) |
| metrics | $($script:CaptureResults.metrics) |
| raw sensitive scan | $($script:CaptureResults.raw_sensitive_scan) |
| overclaim scan | $($script:CaptureResults.overclaim_scan) |
| evidence IDs in reports | $($script:CaptureResults.evidence_ids_in_reports) |
| metrics thesis fields | $($script:CaptureResults.metrics_thesis_fields) |
| **Final** | **$($script:CaptureResults.final)** |

## Outputs

- ``test_results.txt`` — pytest log
- ``api_outputs/`` — safe API JSON/HTML
- ``capture_summary.json`` — machine-readable summary

"@
if ($script:FailureReasons.Count -gt 0) {
    $statusMd += "`n## Failures`n`n"
    foreach ($f in $script:FailureReasons) {
        $statusMd += "- $f`n"
    }
}
Set-Content -Path (Join-Path $script:Phase10EvidenceDir "capture_status.md") -Value $statusMd -Encoding UTF8

Write-Phase10Line "" "White"
if ($script:CaptureResults.final -eq "PASS") {
    Write-Phase10Line "PHASE 10 EVIDENCE CAPTURE: PASS" "Green"
    exit 0
} else {
    Write-Phase10Line "PHASE 10 EVIDENCE CAPTURE: FAIL" "Red"
    foreach ($f in $script:FailureReasons) {
        Write-Phase10Line "  - $f" "Red"
    }
    exit 1
}
