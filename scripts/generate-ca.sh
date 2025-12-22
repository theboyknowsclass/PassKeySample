#!/bin/bash

# Bash script to generate a local Certificate Authority (CA)

echo "Generating local Certificate Authority..."

# Create certs directory structure
mkdir -p certs/ca

CA_KEY="certs/ca/ca.key"
CA_CERT="certs/ca/ca.crt"

# Generate CA private key
if [ ! -f "$CA_KEY" ]; then
    echo "Generating CA private key..."
    openssl genrsa -out "$CA_KEY" 4096
fi

# Generate CA certificate (valid for 10 years)
if [ ! -f "$CA_CERT" ]; then
    echo "Generating CA certificate..."
    
    openssl req -new -x509 -days 3650 -key "$CA_KEY" -out "$CA_CERT" \
        -subj "/C=US/ST=Development/L=Local/O=PassKeySample Development/CN=PassKeySample Local CA" \
        -extensions v3_ca -config <(
            echo "[req]"
            echo "distinguished_name = req_distinguished_name"
            echo ""
            echo "[req_distinguished_name]"
            echo ""
            echo "[v3_ca]"
            echo "basicConstraints = critical,CA:TRUE"
            echo "keyUsage = critical, keyCertSign, cRLSign"
            echo "subjectKeyIdentifier = hash"
            echo "authorityKeyIdentifier = keyid:always,issuer:always"
        )
    
    echo "CA certificate generated successfully!"
    echo "CA Certificate: $CA_CERT"
    echo ""
    echo "To trust this CA on Linux/Mac, run:"
    echo "  sudo cp $CA_CERT /usr/local/share/ca-certificates/passkeysample-ca.crt"
    echo "  sudo update-ca-certificates"
    echo ""
    echo "On Mac, you may also need to:"
    echo "  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CA_CERT"
else
    echo "CA already exists at: $CA_CERT"
fi

echo ""
echo "Next steps:"
echo "1. Trust the CA (see commands above)"
echo "2. Generate service certificates: ./scripts/generate-service-certs.sh"

