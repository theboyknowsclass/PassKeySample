# Master script to set up all certificates for the multi-service architecture
# This script generates a CA and all service certificates

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PassKeySample Certificate Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Generate CA
Write-Host "Step 1: Generating Certificate Authority..." -ForegroundColor Green
& "$PSScriptRoot\scripts\generate-ca.ps1"

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to generate CA" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Step 2: Generating service certificates..." -ForegroundColor Green
& "$PSScriptRoot\scripts\generate-service-certs.ps1"

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to generate service certificates" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Certificate Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next step: Trust the CA certificate" -ForegroundColor Yellow
Write-Host "  Run as Administrator: .\scripts\trust-ca.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "This will allow all certificates signed by the CA to be trusted" -ForegroundColor Gray
Write-Host "by your browser and operating system." -ForegroundColor Gray

