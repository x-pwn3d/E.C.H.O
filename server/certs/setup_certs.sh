#!/usr/bin/env bash
set -euo pipefail

# paths
CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$CERT_DIR"

OPENSSL_CONF="$CERT_DIR/openssl_ca.cnf"  
CA_KEY="$CERT_DIR/ca.key"
CA_CRT="$CERT_DIR/ca.crt"
SERIAL_FILE="$CERT_DIR/ca.srl"
INDEX_FILE="$CERT_DIR/index.txt"
SERVER_KEY="$CERT_DIR/server.key"
SERVER_CSR="$CERT_DIR/server.csr"
SERVER_CRT="$CERT_DIR/server.crt"

# check openssl
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not installed or not in PATH. Please install openssl and retry."
  exit 1
fi

# check conf exists
if [ ! -f "$OPENSSL_CONF" ]; then
  echo "File openssl_ca.cnf not found in $CERT_DIR."
  echo "Create or copy an OpenSSL config file there and retry."
  exit 1
fi

# create minimal CA db files if absent
[ -f "$INDEX_FILE" ] || touch "$INDEX_FILE"
[ -f "$SERIAL_FILE" ] || echo "01" > "$SERIAL_FILE"

# create CA key + cert (if absent)
if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CRT" ]; then
  echo "=== Generate CA key and self-signed certificate ==="
  openssl genrsa -out "$CA_KEY" 4096
  openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 -out "$CA_CRT" -config "$OPENSSL_CONF" -extensions v3_ca
  echo "CA created: $CA_CRT"
else
  echo "CA key and certificate already exist: $CA_KEY , $CA_CRT"
fi

# create server key + csr if missing
if [ ! -f "$SERVER_KEY" ]; then
  echo "=== Generate server key ==="
  openssl genrsa -out "$SERVER_KEY" 2048
else
  echo "Server key already exists: $SERVER_KEY"
fi

if [ ! -f "$SERVER_CSR" ]; then
  echo "=== Generate server CSR ==="
  openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -config "$OPENSSL_CONF"
else
  echo "CSR serveur already exists: $SERVER_CSR"
fi

# sign the server csr with the CA (create server.crt)
if [ ! -f "$SERVER_CRT" ]; then
  echo "=== Sign server CSR with CA to create server certificate ==="
  openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial -out "$SERVER_CRT" -days 365 -sha256 -extfile "$OPENSSL_CONF" -extensions v3_req
  echo "Server certificate created: $SERVER_CRT"
else
  echo "Server certificate already exists: $SERVER_CRT"
fi

# copy the CA certificate to client and admin_app if those dirs exist
PROJECT_ROOT="$(cd "$CERT_DIR/.." && pwd)"
CLIENT_DIR="$PROJECT_ROOT/client/certs"
ADMIN_DIR="$PROJECT_ROOT/admin_app"

if [ -d "$CLIENT_DIR" ]; then
  mkdir -p "$CLIENT_DIR"
  cp -f "$CA_CRT" "$CLIENT_DIR/ca.crt"
  echo "Copied $CA_CRT -> $CLIENT_DIR/ca.crt"
fi

if [ -d "$ADMIN_DIR" ]; then
  mkdir -p "$ADMIN_DIR/certs"
  cp -f "$CA_CRT" "$ADMIN_DIR/certs/ca.crt"
  echo "Copied $CA_CRT -> $ADMIN_DIR/certs/ca.crt"
fi

echo
echo "=== Checking generated certificates ==="
echo "CA cert:"
openssl x509 -noout -text -in "$CA_CRT" | sed -n '1,6p'
echo
echo "Server cert subject:"
openssl x509 -noout -subject -in "$SERVER_CRT"
echo "Server cert validity:"
openssl x509 -noout -dates -in "$SERVER_CRT"

echo
echo "=== Certificate setup complete ==="
