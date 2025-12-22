# PowerShell script to trust the local CA certificate
# This must be run as Administrator

Write-Host "Trusting local CA certificate..." -ForegroundColor Green

$caCertPath = "certs\ca\ca.crt"

if (-not (Test-Path $caCertPath)) {
    Write-Host "CA certificate not found at: $caCertPath" -ForegroundColor Red
    Write-Host "Please run .\scripts\generate-ca.ps1 first" -ForegroundColor Yellow
    exit 1
}

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator to trust the certificate." -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
    exit 1
}

try {
    # Import CA certificate to Trusted Root Certification Authorities
    Import-Certificate -FilePath $caCertPath -CertStoreLocation Cert:\LocalMachine\Root
    
    Write-Host "CA certificate trusted successfully!" -ForegroundColor Green
    Write-Host "All certificates signed by this CA will now be trusted by your system." -ForegroundColor Cyan
} catch {
    Write-Host "Failed to trust CA certificate: $_" -ForegroundColor Red
    exit 1
}

