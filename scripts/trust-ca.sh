#!/bin/bash

# Bash script to trust the local CA certificate
# This must be run with sudo on Linux

echo "Trusting local CA certificate..."

CA_CERT="certs/ca/ca.crt"

if [ ! -f "$CA_CERT" ]; then
    echo "CA certificate not found at: $CA_CERT"
    echo "Please run ./scripts/generate-ca.sh first"
    exit 1
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Detected Linux. Copying certificate to system trust store..."
    sudo cp "$CA_CERT" /usr/local/share/ca-certificates/passkeysample-ca.crt
    sudo update-ca-certificates
    echo "CA certificate trusted successfully!"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Detected macOS. Adding certificate to system keychain..."
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CA_CERT"
    echo "CA certificate trusted successfully!"
else
    echo "Unsupported OS. Please manually trust the certificate at: $CA_CERT"
    exit 1
fi

