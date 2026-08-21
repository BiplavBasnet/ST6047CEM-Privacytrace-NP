# PrivacyTrace-NP — Demo environment reset (Phase 7.5)
# Run from project root: .\scripts\demo_reset.ps1
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BackendRoot = Join-Path $ProjectRoot "backend"
$ComposeFile = Join-Path $ProjectRoot "docker-compose.yml"

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Fail([string]$Message) {
    Write-Host ""
    Write-Host "FAILED: $Message" -ForegroundColor Red
    exit 1
}

Write-Step "PrivacyTrace-NP demo reset (project root: $ProjectRoot)"

if (-not (Test-Path $ComposeFile)) {
    Fail "docker-compose.yml not found at $ComposeFile"
}

# Docker daemon must be running (compose v2)
$null = docker info 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    Fail "Docker daemon is not running. Start Docker Desktop and retry."
}

function Invoke-DockerCompose {
    param([string[]]$ComposeArgs)
    # Compose writes progress to stderr; do not treat that as a terminating error.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & docker compose @ComposeArgs 2>&1 | ForEach-Object { Write-Host $_ }
    $exit = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    return $exit
}

Push-Location $ProjectRoot
try {
    Write-Step "Stopping containers and removing database volume (privacytrace_pgdata)"
    if ((Invoke-DockerCompose -ComposeArgs @("down", "-v")) -ne 0) {
        Fail "docker compose down -v failed"
    }

    Write-Step "Starting PostgreSQL via Docker Compose"
    if ((Invoke-DockerCompose -ComposeArgs @("up", "-d")) -ne 0) {
        Fail "docker compose up -d failed"
    }

    Write-Step "Waiting for PostgreSQL to become healthy (max 90s)"
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
        Fail "PostgreSQL did not become healthy within 90 seconds"
    }
    Write-Host "PostgreSQL is healthy." -ForegroundColor Green

    if (-not (Test-Path $BackendRoot)) {
        Fail "Backend folder not found: $BackendRoot"
    }

    Push-Location $BackendRoot
    try {
        $venvPython = Join-Path $BackendRoot ".venv\Scripts\python.exe"
        $python = $null
        if (Test-Path $venvPython) {
            $python = $venvPython
            Write-Step "Using venv Python: $python"
        } else {
            Write-Host "WARNING: .venv not found; using system python on PATH" -ForegroundColor Yellow
            $python = "python"
        }

        Write-Step "Installing requirements (if needed)"
        & $python -m pip install -q -r requirements.txt
        if ($LASTEXITCODE -ne 0) {
            Fail "pip install -r requirements.txt failed"
        }

        Write-Step "Running Alembic migrations (upgrade head)"
        & $python -m alembic upgrade head
        if ($LASTEXITCODE -ne 0) {
            Fail "alembic upgrade head failed"
        }

        Write-Step "Seeding Phase 2 sample data (seed_phase2)"
        & $python -m app.db.seed_phase2
        if ($LASTEXITCODE -ne 0) {
            Fail "python -m app.db.seed_phase2 failed"
        }

        Write-Step "Seeding authenticated demo users (seed_auth_users)"
        & $python -m app.db.seed_auth_users
        if ($LASTEXITCODE -ne 0) {
            Fail "python -m app.db.seed_auth_users failed"
        }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "SUCCESS: Demo reset complete." -ForegroundColor Green
Write-Host "Next: start the API in a second terminal:" -ForegroundColor Yellow
Write-Host "  cd backend" 
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"
Write-Host ""
Write-Host "Then run: .\scripts\demo_smoke_test.ps1" -ForegroundColor Yellow
