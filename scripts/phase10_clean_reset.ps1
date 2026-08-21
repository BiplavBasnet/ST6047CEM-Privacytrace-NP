# PrivacyTrace-NP - Clean reset for Phase 10 demo and evidence capture
# Run from project root: .\scripts\phase10_clean_reset.ps1
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BackendRoot = Join-Path $ProjectRoot "backend"
$ComposeFile = Join-Path $ProjectRoot "docker-compose.yml"

function Write-ResetStep([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Fail-Reset([string]$Message) {
    Write-Host ""
    Write-Host "FAILED: $Message" -ForegroundColor Red
    exit 1
}

Write-ResetStep "PrivacyTrace-NP Phase 10 clean reset"

if (-not (Test-Path $ComposeFile)) {
    Fail-Reset "docker-compose.yml not found at $ComposeFile"
}

$null = docker info 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    Fail-Reset "Docker is not running. Start Docker Desktop and retry."
}

function Invoke-DockerCompose {
    param([string[]]$ComposeArgs)
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & docker compose @ComposeArgs 2>&1 | ForEach-Object { Write-Host $_ }
    $exit = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    return $exit
}

Push-Location $ProjectRoot
try {
    Write-ResetStep "Stopping containers and removing database volume (privacytrace_pgdata)"
    if ((Invoke-DockerCompose -ComposeArgs @("down", "-v")) -ne 0) {
        Fail-Reset "docker compose down -v failed"
    }

    Write-ResetStep "Starting PostgreSQL via Docker Compose"
    if ((Invoke-DockerCompose -ComposeArgs @("up", "-d")) -ne 0) {
        Fail-Reset "docker compose up -d failed"
    }

    Write-ResetStep "Waiting for PostgreSQL to become healthy (max 90s)"
    $deadline = (Get-Date).AddSeconds(90)
    $healthy = $false
    while ((Get-Date) -lt $deadline) {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $health = docker inspect --format "{{.State.Health.Status}}" privacytrace-np-postgres 2>&1
        $inspectExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEap
        if ($inspectExit -eq 0 -and $health -eq "healthy") {
            $healthy = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $healthy) {
        docker compose ps 2>&1 | ForEach-Object { Write-Host $_ }
        Fail-Reset "PostgreSQL did not become healthy within 90 seconds"
    }
    Write-Host "PostgreSQL is healthy." -ForegroundColor Green

    Push-Location $BackendRoot
    try {
        $venvPython = Join-Path $BackendRoot ".venv\Scripts\python.exe"
        if (Test-Path $venvPython) {
            $python = $venvPython
            Write-ResetStep "Using venv Python: $python"
        } else {
            Fail-Reset "Python venv not found at $venvPython. Create it with: python -m venv .venv"
        }

        Write-ResetStep "Installing requirements"
        & $python -m pip install -q -r requirements.txt
        if ($LASTEXITCODE -ne 0) { Fail-Reset "pip install -r requirements.txt failed" }

        Write-ResetStep "Running alembic upgrade head"
        & $python -m alembic upgrade head
        if ($LASTEXITCODE -ne 0) { Fail-Reset "alembic upgrade head failed" }

        Write-ResetStep "Seeding Phase 2 sample data (seed_phase2)"
        & $python -m app.db.seed_phase2
        if ($LASTEXITCODE -ne 0) { Fail-Reset "python -m app.db.seed_phase2 failed" }

        Write-ResetStep "Seeding authenticated demo users (seed_auth_users)"
        & $python -m app.db.seed_auth_users
        if ($LASTEXITCODE -ne 0) { Fail-Reset "python -m app.db.seed_auth_users failed" }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "SUCCESS: Phase 10 clean reset complete." -ForegroundColor Green
Write-Host ""
Write-Host "Next - start the API in a separate terminal:" -ForegroundColor Yellow
Write-Host "  cd backend"
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"
Write-Host ""
Write-Host "Then run:" -ForegroundColor Yellow
Write-Host "  .\scripts\phase10_prepare_workflow.ps1"
Write-Host "  .\scripts\capture_phase10_evidence.ps1"
