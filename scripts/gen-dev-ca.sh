#!/bin/bash
# scripts/gen-dev-ca.sh
set -e

# ==============================================================================
# WINDOWS / GIT BASH COMPATIBILITY FIXES
# ==============================================================================
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    export MSYS_NO_PATHCONV=1
fi

unset OPENSSL_CONF
# ==============================================================================

# Configuration
CERTS_DIR="certs"
SERVER_IP="16.171.151.222"
CLIENT_NAME="flutter-client-sdk"

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "🔐 Bootstrapping Strict Zero-Trust PKI Infrastructure..."

# ------------------------------------------------------------------------------
# 1. GENERATE STRICT ROOT CA
# ------------------------------------------------------------------------------
if [ ! -f ca.key ]; then
    echo "   Generating Root CA (4096-bit)..."
    openssl genrsa -out ca.key 4096

    cat > ca-ext.cnf << EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions    = v3_ca
prompt             = no

[ req_distinguished_name ]
CN = Invariant Root CA

[ v3_ca ]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
EOF

    openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -config ca-ext.cnf
else
    echo "   Root CA already exists. Skipping generation to maintain trust anchor."
fi

# ------------------------------------------------------------------------------
# 2. GENERATE STRICT SERVER CERTIFICATE
# ------------------------------------------------------------------------------
echo "   Generating Server Certificate (2048-bit)..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=$SERVER_IP"

# Explicit constraints: Not a CA, limited to Server Authentication, binds IP only
cat > server-ext.cnf << EOF
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName         = IP:$SERVER_IP
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -sha256 -extfile server-ext.cnf

# ------------------------------------------------------------------------------
# 3. GENERATE STRICT CLIENT CERTIFICATE
# ------------------------------------------------------------------------------
echo "   Generating Client Certificate (2048-bit)..."
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=$CLIENT_NAME"

# Explicit constraints: Not a CA, limited to Client Authentication ONLY
cat > client-ext.cnf << EOF
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 30 -sha256 -extfile client-ext.cnf

# ------------------------------------------------------------------------------
# 4. EXPORT PKCS#12 BUNDLE FOR FLUTTER
# ------------------------------------------------------------------------------
echo "   Bundling Client Certificate for Flutter SDK..."
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.crt -passout pass:invariant

# ------------------------------------------------------------------------------
# 5. CLEANUP
# ------------------------------------------------------------------------------
rm -f *.csr *-ext.cnf *.srl

echo "✅ Strict PKI Generation Complete."
echo "   -> Server SAN: IP:$SERVER_IP"
echo "   -> Flutter Bundle: certs/client.p12 (Password: invariant)"