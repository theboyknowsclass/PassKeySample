# PowerShell script to generate a local Certificate Authority (CA)
# This CA will be used to sign certificates for all services

Write-Host "Generating local Certificate Authority..." -ForegroundColor Green

# Create certs directory structure
$certsDir = "certs"
$caDir = Join-Path $certsDir "ca"

if (-not (Test-Path $certsDir)) {
    New-Item -ItemType Directory -Path $certsDir | Out-Null
}

if (-not (Test-Path $caDir)) {
    New-Item -ItemType Directory -Path $caDir | Out-Null
}

# Check if OpenSSL is available (required for CA generation)
$opensslPath = Get-Command openssl -ErrorAction SilentlyContinue

if (-not $opensslPath) {
    Write-Host "OpenSSL is required but not found. Installing via winget..." -ForegroundColor Yellow
    
    # Try to install OpenSSL via winget
    winget install ShiningLight.OpenSSL.Light --accept-package-agreements --accept-source-agreements
    
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    
    $opensslPath = Get-Command openssl -ErrorAction SilentlyContinue
    if (-not $opensslPath) {
        Write-Host "Failed to install OpenSSL. Please install it manually from https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Red
        exit 1
    }
}

$caKeyPath = Join-Path $caDir "ca.key"
$caCertPath = Join-Path $caDir "ca.crt"

# Generate CA private key
if (-not (Test-Path $caKeyPath)) {
    Write-Host "Generating CA private key..." -ForegroundColor Yellow
    & openssl genrsa -out $caKeyPath 4096
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to generate CA key" -ForegroundColor Red
        exit 1
    }
}

# Generate CA certificate (valid for 10 years)
if (-not (Test-Path $caCertPath)) {
    Write-Host "Generating CA certificate..." -ForegroundColor Yellow
    
    # Create CA config file
    $caConfig = @"
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
C = US
ST = Development
L = Local
O = PassKeySample Development
CN = PassKeySample Local CA

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
"@
    
    $caConfigPath = Join-Path $caDir "ca.conf"
    $caConfig | Out-File -FilePath $caConfigPath -Encoding ASCII
    
    & openssl req -new -x509 -days 3650 -key $caKeyPath -out $caCertPath -config $caConfigPath -extensions v3_ca
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to generate CA certificate" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "CA certificate generated successfully!" -ForegroundColor Green
    Write-Host "CA Certificate: $caCertPath" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To trust this CA, run:" -ForegroundColor Cyan
    Write-Host "  Import-Certificate -FilePath `"$caCertPath`" -CertStoreLocation Cert:\LocalMachine\Root" -ForegroundColor White
} else {
    Write-Host "CA already exists at: $caCertPath" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Green
Write-Host "1. Trust the CA: .\scripts\trust-ca.ps1" -ForegroundColor Cyan
Write-Host "2. Generate service certificates: .\scripts\generate-service-certs.ps1" -ForegroundColor Cyan

