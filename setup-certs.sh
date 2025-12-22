#!/bin/bash

# Bash script to generate development certificate
echo "Generating development certificate..."

# Create certs directory if it doesn't exist
mkdir -p certs

# Generate and export certificate
dotnet dev-certs https --export-path ./certs/aspnetapp.pfx --password PassKeySample123!

if [ $? -eq 0 ]; then
    echo "Certificate generated successfully!"
    echo "Certificate location: ./certs/aspnetapp.pfx"
else
    echo "Failed to generate certificate. Make sure .NET 8 SDK is installed."
    exit 1
fi

