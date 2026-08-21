# Call security self-check API (requires running backend and admin token)

param(
    [string]$BaseUrl = "http://127.0.0.1:8000",
    [string]$Email = "admin@privacytrace.local",
    [string]$Password = "AdminPass123!"
)

$ErrorActionPreference = "Stop"
$loginBody = @{ email = $Email; password = $Password } | ConvertTo-Json
$login = Invoke-RestMethod -Uri "$BaseUrl/auth/login" -Method Post -Body $loginBody -ContentType "application/json"
$token = $login.access_token
$headers = @{ Authorization = "Bearer $token" }

$profile = Invoke-RestMethod -Uri "$BaseUrl/security/profile" -Headers $headers
$check = Invoke-RestMethod -Uri "$BaseUrl/security/self-check" -Headers $headers

Write-Host "=== Security profile ==="
$profile | ConvertTo-Json -Depth 5
Write-Host "=== Self-check ==="
$check | ConvertTo-Json -Depth 5
