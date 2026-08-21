# PrivacyTrace-NP Phase 10 shared helpers (dot-source from other scripts)
# Usage: . "$PSScriptRoot\phase10_common.ps1"

$script:Phase10ProjectRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { Get-Location }
$script:Phase10EvidenceDir = Join-Path $script:Phase10ProjectRoot "docs\evidence_pack"
$script:Phase10ApiOutDir = Join-Path $script:Phase10EvidenceDir "api_outputs"
$script:Phase10BackendDir = Join-Path $script:Phase10ProjectRoot "backend"
$script:Phase10BaseUrl = if ($env:PRIVACYTRACE_BASE_URL) { $env:PRIVACYTRACE_BASE_URL } else { "http://127.0.0.1:8000" }
$script:Phase10IncidentId = "INC-SEED-001"
$script:Phase10AuthEmail = if ($env:PRIVACYTRACE_TEST_EMAIL) { $env:PRIVACYTRACE_TEST_EMAIL } else { "analyst@privacytrace.local" }
$script:Phase10AuthPassword = if ($env:PRIVACYTRACE_TEST_PASSWORD) { $env:PRIVACYTRACE_TEST_PASSWORD } else { "AnalystPass123!" }
$script:Phase10AuthToken = $null

$script:Phase10BlockedRaw = @(
    "9841234567",
    "WALLET-NP-88291",
    "pk_test_np_fake_12345"
)
$script:Phase10BlockedRawRegex = @(
    '(?i)authorization\s*:\s*bearer\s+',
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    '(?i)bearer\s+eyJ'
)
$script:Phase10BlockedOverclaim = @(
    "proven cause",
    "confirmed blame",
    "guaranteed cause",
    "definitely caused by",
    "developer fault",
    "guaranteed fixed",
    "incident closed automatically"
)
$script:Phase10RequiredMetrics = @(
    "detection_precision",
    "detection_recall",
    "detection_f1_score",
    "masking_effectiveness",
    "raw_sensitive_value_leak_count",
    "root_cause_top_1_accuracy",
    "root_cause_top_3_accuracy",
    "evidence_faithfulness_score",
    "llm_overclaim_violation_count",
    "time_to_causal_localisation",
    "fix_verification_success_rate",
    "human_review_completion_rate"
)

function Initialize-Phase10EvidenceDirs {
    New-Item -ItemType Directory -Force -Path $script:Phase10EvidenceDir | Out-Null
    New-Item -ItemType Directory -Force -Path $script:Phase10ApiOutDir | Out-Null
}

function Write-Phase10Line {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Get-Phase10OverclaimScanBlob {
    param([string]$Blob)
    $scrubbed = [regex]::Replace($Blob, '"validation_errors"\s*:\s*\[[^\]]*\]', '"validation_errors":[]')
    $scrubbed = [regex]::Replace($scrubbed, '(?i)not confirmed blame', 'NEGATED_BLAME')
    $scrubbed = [regex]::Replace($scrubbed, '(?i)not proven cause', 'NEGATED_PROVEN')
    $scrubbed = [regex]::Replace($scrubbed, '(?i)must not claim definite proof or confirmed blame', 'NEGATED_PROMPT')
    $scrubbed = [regex]::Replace($scrubbed, '(?i)forbidden_categories', 'POLICY_CATEGORIES')
    return $scrubbed
}

function Test-Phase10SafeContent {
    param(
        [string]$Label,
        [string]$Blob,
        [switch]$SkipRawScan
    )
    $violations = @()
    if (-not $SkipRawScan) {
        foreach ($raw in $script:Phase10BlockedRaw) {
            if ($Blob -like "*$raw*") { $violations += "blocked raw value '$raw'" }
        }
        foreach ($pat in $script:Phase10BlockedRawRegex) {
            if ($Blob -match $pat) { $violations += "blocked pattern '$pat'" }
        }
    }
    $lower = (Get-Phase10OverclaimScanBlob $Blob).ToLowerInvariant()
    foreach ($phrase in $script:Phase10BlockedOverclaim) {
        if ($lower.Contains($phrase)) { $violations += "overclaim phrase '$phrase'" }
    }
    if ($violations.Count -gt 0) {
        return @{ Ok = $false; Violations = $violations }
    }
    return @{ Ok = $true; Violations = @() }
}

function Save-Phase10SafeJson {
    param(
        [string]$Name,
        $Object
    )
    Initialize-Phase10EvidenceDirs
    $path = Join-Path $script:Phase10ApiOutDir $Name
    $json = $Object | ConvertTo-Json -Depth 30
    Set-Content -Path $path -Value $json -Encoding UTF8
    $check = Test-Phase10SafeContent -Label $Name -Blob $json
    if (-not $check.Ok) {
        throw "$Name failed safety scan: $($check.Violations -join '; ')"
    }
    return $path
}

function Save-Phase10SafeHtml {
    param(
        [string]$Name,
        [string]$Html
    )
    Initialize-Phase10EvidenceDirs
    $path = Join-Path $script:Phase10ApiOutDir $Name
    Set-Content -Path $path -Value $Html -Encoding UTF8
    $check = Test-Phase10SafeContent -Label $Name -Blob $Html
    if (-not $check.Ok) {
        throw "$Name failed safety scan: $($check.Violations -join '; ')"
    }
    return $path
}

function Get-Phase10AuthHeaders {
    if (-not $script:Phase10AuthToken) {
        $loginBody = @{
            email    = $script:Phase10AuthEmail
            password = $script:Phase10AuthPassword
        } | ConvertTo-Json -Compress
        try {
            $login = Invoke-RestMethod -Uri "$($script:Phase10BaseUrl)/auth/login" -Method Post -ContentType "application/json" -Body $loginBody -TimeoutSec 30
        } catch {
            throw "Authentication failed for $($script:Phase10AuthEmail). Run the auth-user seed and verify PRIVACYTRACE_TEST_EMAIL/PRIVACYTRACE_TEST_PASSWORD."
        }
        if (-not $login.access_token) {
            throw "Authentication response did not include access_token."
        }
        $script:Phase10AuthToken = $login.access_token
    }
    return @{ Authorization = "Bearer $($script:Phase10AuthToken)" }
}

function Invoke-Phase10Api {
    param(
        [string]$Method,
        [string]$Path,
        $Body = $null
    )
    $uri = "$($script:Phase10BaseUrl)$Path"
    $headers = Get-Phase10AuthHeaders
    if ($Method -eq "GET") {
        return Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 120
    }
    $jsonBody = if ($null -ne $Body) { $Body | ConvertTo-Json -Compress -Depth 10 } else { "{}" }
    return Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -ContentType "application/json" -Body $jsonBody -TimeoutSec 120
}

function Invoke-Phase10MultipartUpload {
    param(
        [string]$Path,
        [string]$FilePath,
        [hashtable]$Fields
    )
    $uri = "$($script:Phase10BaseUrl)$Path"
    if (-not (Test-Path -LiteralPath $FilePath)) {
        throw "Upload file not found: $FilePath"
    }
    $headers = Get-Phase10AuthHeaders

    # Prefer curl.exe for broad Windows PowerShell 5.1 compatibility.
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        $args = @("-sS", "-X", "POST", $uri, "-H", "Authorization: $($headers.Authorization)", "-F", "file=@$FilePath")
        foreach ($key in $Fields.Keys) {
            if ($key -eq "file") { continue }
            $args += "-F"
            $args += "$key=$($Fields[$key])"
        }
        $raw = & curl.exe @args 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "curl upload failed: $raw"
        }
        return ($raw | Out-String).Trim() | ConvertFrom-Json
    }

    Add-Type -AssemblyName System.Net.Http
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [TimeSpan]::FromSeconds(120)
    $client.DefaultRequestHeaders.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new("Bearer", $script:Phase10AuthToken)
    $fileStream = $null
    try {
        $content = New-Object System.Net.Http.MultipartFormDataContent
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        $fileStream = [System.IO.File]::OpenRead($FilePath)
        $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
        $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")
        $content.Add($fileContent, "file", $fileName)
        foreach ($key in $Fields.Keys) {
            if ($key -eq "file") { continue }
            $stringContent = New-Object System.Net.Http.StringContent([string]$Fields[$key])
            $content.Add($stringContent, $key)
        }
        $response = $client.PostAsync($uri, $content).GetAwaiter().GetResult()
        $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) {
            throw "Upload failed ($([int]$response.StatusCode)): $responseBody"
        }
        return $responseBody | ConvertFrom-Json
    } finally {
        if ($fileStream) { $fileStream.Dispose() }
        $client.Dispose()
    }
}

function Test-Phase10BackendReachable {
    try {
        $null = Invoke-WebRequest -Uri "$($script:Phase10BaseUrl)/health" -UseBasicParsing -TimeoutSec 5
        return $true
    } catch {
        return $false
    }
}

function Get-Phase10Health {
    try {
        $response = Invoke-WebRequest -Uri "$($script:Phase10BaseUrl)/health" -UseBasicParsing -TimeoutSec 10
        $body = $response.Content | ConvertFrom-Json
        return @{
            Reachable = $true
            StatusCode = [int]$response.StatusCode
            Body = $body
        }
    } catch {
        $statusCode = $null
        $body = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode.value__
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $raw = $reader.ReadToEnd()
                $reader.Close()
                if ($raw) { $body = $raw | ConvertFrom-Json }
            } catch { }
        }
        return @{
            Reachable = $false
            StatusCode = $statusCode
            Body = $body
            Error = $_.Exception.Message
        }
    }
}

function Assert-Phase10HealthReady {
    if (-not (Test-Phase10BackendReachable)) {
        throw @"
Backend is not running at $($script:Phase10BaseUrl).

Start the API in a separate terminal:
  cd backend
  .\.venv\Scripts\Activate.ps1
  uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
"@
    }
    $health = Get-Phase10Health
    if ($health.StatusCode -eq 503 -or ($health.Body -and $health.Body.database -ne "connected")) {
        throw @"
Backend is running but the database is not connected.

Reset and prepare the database:
  .\scripts\phase10_clean_reset.ps1

Then start uvicorn again and retry.
"@
    }
    if ($health.Body.status -notin @("healthy", "ok")) {
        throw "Health check returned unexpected status: $($health.Body.status)"
    }
    if ($health.Body.database -ne "connected") {
        throw "Health check database field is not 'connected' (got '$($health.Body.database)')."
    }
    return $health.Body
}

function Test-Phase10BlobHasEvidenceIds {
    param([string]$Blob)
    return $Blob -match 'EVD-S1-[A-Z0-9-]+'
}

function Test-Phase10BlobHasLikelyWording {
    param([string]$Blob)
    return $Blob -match '(?i)likely'
}

function Upload-Phase10SafeRetestEvidence {
    $sampleRetest = Join-Path $script:Phase10BackendDir "app\sample_data\retest_evidence\wallet_transfer_retest.log"
    if (-not (Test-Path $sampleRetest)) {
        throw "Safe retest sample not found: $sampleRetest"
    }
    $uniqueRetest = [System.IO.Path]::GetTempFileName() + ".log"
    try {
        $baseContent = Get-Content -Path $sampleRetest -Raw -Encoding UTF8
        $runTag = [Guid]::NewGuid().ToString("n").Substring(0, 8)
        Set-Content -Path $uniqueRetest -Value ($baseContent + "`n# phase10-run $runTag`n") -Encoding UTF8 -NoNewline
        $uploadResp = Invoke-Phase10MultipartUpload -Path "/evidence/upload" -FilePath $uniqueRetest -Fields @{
            evidence_type      = "fixed_log"
            linked_incident_id = $script:Phase10IncidentId
        }
        $eid = $uploadResp.evidence_id
        if (-not $eid -and $uploadResp.evidence) { $eid = $uploadResp.evidence.evidence_id }
        if (-not $eid) { throw "Upload retest evidence did not return evidence_id" }
        Save-Phase10SafeJson -Name "retest_evidence_upload.json" -Object $uploadResp | Out-Null
        return $eid
    } finally {
        if ($uniqueRetest -and (Test-Path $uniqueRetest)) {
            Remove-Item -LiteralPath $uniqueRetest -Force -ErrorAction SilentlyContinue
        }
    }
}

function Scan-Phase10AllApiOutputs {
    $failures = @()
    Get-ChildItem -Path $script:Phase10ApiOutDir -File -ErrorAction SilentlyContinue | ForEach-Object {
        $blob = Get-Content -Path $_.FullName -Raw -Encoding UTF8
        $check = Test-Phase10SafeContent -Label $_.Name -Blob $blob
        if (-not $check.Ok) {
            foreach ($v in $check.Violations) { $failures += "$($_.Name): $v" }
        }
    }
    return $failures
}
