#!/bin/bash

# Bash script to generate certificates for each service

SERVICES=("api" "frontend" "keycloak")

echo "Generating service certificates..."

CA_KEY="certs/ca/ca.key"
CA_CERT="certs/ca/ca.crt"

# Verify CA exists
if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CERT" ]; then
    echo "CA not found. Please run ./scripts/generate-ca.sh first"
    exit 1
fi

for service in "${SERVICES[@]}"; do
    echo ""
    echo "Generating certificate for: $service"
    
    mkdir -p "certs/$service"
    
    SERVICE_KEY="certs/$service/$service.key"
    SERVICE_CSR="certs/$service/$service.csr"
    SERVICE_CERT="certs/$service/$service.crt"
    SERVICE_PFX="certs/$service/$service.pfx"
    
    # Generate private key
    if [ ! -f "$SERVICE_KEY" ]; then
        openssl genrsa -out "$SERVICE_KEY" 2048
    fi
    
    # Generate certificate signing request
    openssl req -new -key "$SERVICE_KEY" -out "$SERVICE_CSR" \
        -subj "/C=US/ST=Development/L=Local/O=PassKeySample Development/CN=$service.localhost" \
        -config <(
            echo "[req]"
            echo "distinguished_name = req_distinguished_name"
            echo "req_extensions = v3_req"
            echo ""
            echo "[req_distinguished_name]"
            echo ""
            echo "[v3_req]"
            echo "basicConstraints = CA:FALSE"
            echo "keyUsage = nonRepudiation, digitalSignature, keyEncipherment"
            echo "subjectAltName = @alt_names"
            echo ""
            echo "[alt_names]"
            echo "DNS.1 = localhost"
            echo "DNS.2 = $service.localhost"
            echo "IP.1 = 127.0.0.1"
        )
    
    # Sign certificate with CA (valid for 1 year)
    openssl x509 -req -in "$SERVICE_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
        -out "$SERVICE_CERT" -days 365 -extensions v3_req \
        -extfile <(
            echo "[v3_req]"
            echo "basicConstraints = CA:FALSE"
            echo "keyUsage = nonRepudiation, digitalSignature, keyEncipherment"
            echo "subjectAltName = @alt_names"
            echo ""
            echo "[alt_names]"
            echo "DNS.1 = localhost"
            echo "DNS.2 = $service.localhost"
            echo "IP.1 = 127.0.0.1"
        )
    
    # Convert to PFX for .NET (if needed)
    if [ "$service" = "api" ]; then
        openssl pkcs12 -export -out "$SERVICE_PFX" -inkey "$SERVICE_KEY" -in "$SERVICE_CERT" \
            -password "pass:PassKeySample123!" -name "$service"
        echo "  PFX created: $SERVICE_PFX"
    fi
    
    echo "  Certificate created: $SERVICE_CERT"
done

echo ""
echo "All service certificates generated successfully!"

