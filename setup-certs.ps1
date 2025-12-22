# PowerShell script to generate development certificate
Write-Host "Generating development certificate..." -ForegroundColor Green

# Create certs directory if it doesn't exist
if (-not (Test-Path "certs")) {
    New-Item -ItemType Directory -Path "certs" | Out-Null
}

# Generate and export certificate
dotnet dev-certs https --export-path ./certs/aspnetapp.pfx --password PassKeySample123!

if ($LASTEXITCODE -eq 0) {
    Write-Host "Certificate generated successfully!" -ForegroundColor Green
    Write-Host "Certificate location: ./certs/aspnetapp.pfx" -ForegroundColor Yellow
} else {
    Write-Host "Failed to generate certificate. Make sure .NET 8 SDK is installed." -ForegroundColor Red
    exit 1
}

