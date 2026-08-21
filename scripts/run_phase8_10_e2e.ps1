param(
    [switch]$Keep
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BackendPython = Join-Path $ProjectRoot "backend\.venv\Scripts\python.exe"
$Runner = Join-Path $ProjectRoot "scripts\run_backend_tests_with_postgres.py"

if (-not (Test-Path $BackendPython)) {
    throw "Backend virtual environment not found at $BackendPython"
}
if (-not (Test-Path $Runner)) {
    throw "Isolated PostgreSQL runner not found at $Runner"
}

$arguments = @($Runner)
if ($Keep) { $arguments += "--keep" }
$arguments += "-v"

& $BackendPython @arguments
exit $LASTEXITCODE
