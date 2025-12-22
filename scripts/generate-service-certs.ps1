# PowerShell script to generate certificates for each service
# All certificates will be signed by the local CA

param(
    [Parameter(Mandatory=$false)]
    [string[]]$Services = @("api", "frontend", "keycloak")
)

Write-Host "Generating service certificates..." -ForegroundColor Green

$certsDir = "certs"
$caDir = Join-Path $certsDir "ca"
$caKeyPath = Join-Path $caDir "ca.key"
$caCertPath = Join-Path $caDir "ca.crt"

# Verify CA exists
if (-not (Test-Path $caKeyPath) -or -not (Test-Path $caCertPath)) {
    Write-Host "CA not found. Please run .\scripts\generate-ca.ps1 first" -ForegroundColor Red
    exit 1
}

$opensslPath = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $opensslPath) {
    Write-Host "OpenSSL is required but not found." -ForegroundColor Red
    exit 1
}

foreach ($service in $services) {
    Write-Host ""
    Write-Host "Generating certificate for: $service" -ForegroundColor Yellow
    
    $serviceDir = Join-Path $certsDir $service
    if (-not (Test-Path $serviceDir)) {
        New-Item -ItemType Directory -Path $serviceDir | Out-Null
    }
    
    $serviceKeyPath = Join-Path $serviceDir "$service.key"
    $serviceCsrPath = Join-Path $serviceDir "$service.csr"
    $serviceCertPath = Join-Path $serviceDir "$service.crt"
    $servicePfxPath = Join-Path $serviceDir "$service.pfx"
    $serviceConfigPath = Join-Path $serviceDir "$service.conf"
    
    # Service-specific configuration
    $subjectAltNames = switch ($service) {
        "api" { "DNS:localhost,DNS:api.localhost,IP:127.0.0.1" }
        "frontend" { "DNS:localhost,DNS:frontend.localhost,IP:127.0.0.1" }
        "keycloak" { "DNS:localhost,DNS:keycloak.localhost,IP:127.0.0.1" }
        default { "DNS:localhost,DNS:$service.localhost,IP:127.0.0.1" }
    }
    
    # Create service certificate config
    $serviceConfig = @"
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Development
L = Local
O = PassKeySample Development
CN = $service.localhost

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = $service.localhost
IP.1 = 127.0.0.1
"@
    
    $serviceConfig | Out-File -FilePath $serviceConfigPath -Encoding ASCII
    
    # Generate private key
    if (-not (Test-Path $serviceKeyPath)) {
        & openssl genrsa -out $serviceKeyPath 2048
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Failed to generate key for $service" -ForegroundColor Red
            continue
        }
    }
    
    # Generate certificate signing request
    & openssl req -new -key $serviceKeyPath -out $serviceCsrPath -config $serviceConfigPath
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to generate CSR for $service" -ForegroundColor Red
        continue
    }
    
    # Sign certificate with CA (valid for 1 year)
    & openssl x509 -req -in $serviceCsrPath -CA $caCertPath -CAkey $caKeyPath -CAcreateserial -out $serviceCertPath -days 365 -extensions v3_req -extfile $serviceConfigPath
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to sign certificate for $service" -ForegroundColor Red
        continue
    }
    
    # Convert to PFX for .NET (if needed)
    if ($service -eq "api") {
        $pfxPassword = "PassKeySample123!"
        & openssl pkcs12 -export -out $servicePfxPath -inkey $serviceKeyPath -in $serviceCertPath -password "pass:$pfxPassword" -name "$service"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  PFX created: $servicePfxPath" -ForegroundColor Green
        }
    }
    
    Write-Host "  Certificate created: $serviceCertPath" -ForegroundColor Green
}

Write-Host ""
Write-Host "All service certificates generated successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Certificate locations:" -ForegroundColor Cyan
foreach ($service in $services) {
    $serviceDir = Join-Path $certsDir $service
    Write-Host "  $service`: $serviceDir" -ForegroundColor Yellow
}

