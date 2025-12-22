#!/bin/bash

# Master script to set up all certificates for the multi-service architecture

echo "========================================"
echo "PassKeySample Certificate Setup"
echo "========================================"
echo ""

# Step 1: Generate CA
echo "Step 1: Generating Certificate Authority..."
./scripts/generate-ca.sh

if [ $? -ne 0 ]; then
    echo "Failed to generate CA"
    exit 1
fi

echo ""
echo "Step 2: Generating service certificates..."
./scripts/generate-service-certs.sh

if [ $? -ne 0 ]; then
    echo "Failed to generate service certificates"
    exit 1
fi

echo ""
echo "========================================"
echo "Certificate Setup Complete!"
echo "========================================"
echo ""
echo "Next step: Trust the CA certificate"
echo "  Run: ./scripts/trust-ca.sh"
echo ""
echo "This will allow all certificates signed by the CA to be trusted"
echo "by your browser and operating system."

