#!/bin/bash
# scripts/gen-dev-ca.sh
set -e

# ==============================================================================
# WINDOWS / GIT BASH COMPATIBILITY FIXES
# ==============================================================================
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    # 1. Prevent Git Bash from converting /CN=... into C:/Program Files/Git/...
    export MSYS_NO_PATHCONV=1
fi

# 2. Clear poisoned environment variables (e.g., from PostgreSQL installations)
# By unsetting this, OpenSSL will naturally fall back to its internal defaults.
unset OPENSSL_CONF
# ==============================================================================

mkdir -p certs && cd certs

SERVER_IP="16.171.151.222"

# 1. Generate Private Root CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=Invariant Root CA"

# 2. Generate Server Certificate Request
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=$SERVER_IP"

# Create Extension File for IP Subject Alternative Name (SAN)
# This is MANDATORY for raw IP TLS validation in modern clients.
cat > server-ext.cnf << EOF
subjectAltName = IP:$SERVER_IP
EOF

# 3. Sign Server Certificate with the SAN extension
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile server-ext.cnf

# 4. Generate Client Certificate
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=flutter-client-node"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 30 -sha256

# 5. Bundle into PKCS#12 format suitable for Flutter local testing
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.crt -passout pass:invariant

# Cleanup temp files
rm server-ext.cnf server.csr client.csr

echo "✅ Certificates successfully generated for IP: $SERVER_IP"