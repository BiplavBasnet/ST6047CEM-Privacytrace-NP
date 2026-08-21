# PrivacyTrace-NP — generate demo-only RSA key pairs (Phase 11.7)
# WARNING: Demo keys only. Never commit private keys. Never use in production.

$ErrorActionPreference = "Stop"
$BackendRoot = Resolve-Path (Join-Path (Join-Path $PSScriptRoot "..") "backend")
$KeysDir = Join-Path (Join-Path $BackendRoot "keys") "demo"
New-Item -ItemType Directory -Force -Path $KeysDir | Out-Null

$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) {
    Write-Error "OpenSSL is required. Install OpenSSL and ensure it is on PATH."
}

$jwtPriv = Join-Path $KeysDir "jwt_private.pem"
$jwtPub = Join-Path $KeysDir "jwt_public.pem"
$wrapPriv = Join-Path $KeysDir "data_wrap_private.pem"
$wrapPub = Join-Path $KeysDir "data_wrap_public.pem"

& openssl genrsa -out $jwtPriv 4096
& openssl rsa -in $jwtPriv -pubout -out $jwtPub
& openssl genrsa -out $wrapPriv 4096
& openssl rsa -in $wrapPriv -pubout -out $wrapPub

Write-Host "Demo keys written to: $KeysDir"
Write-Host "Set environment variables (relative to backend/ when starting uvicorn):"
Write-Host "  JWT_PRIVATE_KEY_PATH=keys/demo/jwt_private.pem"
Write-Host "  JWT_PUBLIC_KEY_PATH=keys/demo/jwt_public.pem"
Write-Host "  DATA_KEY_PRIVATE_KEY_PATH=keys/demo/data_wrap_private.pem"
Write-Host "  DATA_KEY_PUBLIC_KEY_PATH=keys/demo/data_wrap_public.pem"
Write-Host "  CRYPTO_ACTIVE_KEY_ID=demo-key-001"
Write-Host "  CRYPTO_ENCRYPTION_ENABLED=true"
Write-Host "Private keys are gitignored under backend/keys/"
