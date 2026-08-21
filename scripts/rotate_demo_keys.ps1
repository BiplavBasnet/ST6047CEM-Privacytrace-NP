# Rotate demo RSA keys — backs up existing keys then regenerates (Phase 11.7)

$ErrorActionPreference = "Stop"
$BackendRoot = Resolve-Path (Join-Path (Join-Path $PSScriptRoot "..") "backend")
$KeysDir = Join-Path (Join-Path $BackendRoot "keys") "demo"
$BackupDir = Join-Path (Join-Path $BackendRoot "keys") "demo_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

if (Test-Path $KeysDir) {
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    Copy-Item -Path (Join-Path $KeysDir "*.pem") -Destination $BackupDir -ErrorAction SilentlyContinue
    Write-Host "Backed up previous keys to: $BackupDir"
}

& (Join-Path $PSScriptRoot "generate_demo_keys.ps1")
Write-Host "Update CRYPTO_ACTIVE_KEY_ID if you use key versioning (e.g. demo-key-002)."
Write-Host "Re-login is required: existing JWTs signed with the old private key will fail verification."
