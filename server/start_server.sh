#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$ROOT/certs"

# generate ephemeral token for this run
ECHO_AUTH_TOKEN="$(python3 - <<'PY'
import secrets, sys
print(secrets.token_urlsafe(32))
PY
)"

export ECHO_AUTH_TOKEN="$ECHO_AUTH_TOKEN"   
export ECHO_CA="$CERT_DIR/ca.crt"
export ECHO_SERVER="https://localhost:8443"

GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"

echo -e "${GREEN}"
echo "======================================================="
echo "  E.C.H.O - ephemeral C2 token for this run (v0.1.0)"
echo -e "  TOKEN : ${YELLOW}${ECHO_AUTH_TOKEN}${GREEN}"
echo "======================================================="
echo -e "${RESET}"

# check certs exist
if [ ! -f "$CERT_DIR/server.crt" ] || [ ! -f "$CERT_DIR/server.key" ]; then
  echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${RESET}" >&2
  echo -e "${RED} ERROR: Certificates not found in ${CERT_DIR}.${RESET}" >&2
  echo -e "${RED} Please run ./certs/setup_certs.sh first.${RESET}" >&2
  echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${RESET}" >&2
  echo -ne "\a" >&2
  exit 2
fi

# quick sanity check for SAN (non-blocking) - warn if localhost/127.0.0.1 not present
SAN_OK=1
if command -v openssl >/dev/null 2>&1; then
  if ! openssl x509 -in "$CERT_DIR/server.crt" -noout -ext subjectAltName 2>/dev/null | grep -q -E "localhost|127\.0\.0\.1"; then
    SAN_OK=0
  fi
else
  SAN_OK=0
fi

if [ "$SAN_OK" -eq 0 ]; then
  echo -e "${YELLOW}---------------------------------------------------------------${RESET}" >&2
  echo -e "${YELLOW} WARNING: server.crt doesn't appear to contain localhost/127.0.0.1 in the SAN.${RESET}" >&2
  echo -e "${YELLOW} This may trigger TLS hostname verification errors in clients.${RESET}" >&2
  echo -e "${YELLOW} If you're using curl for quick tests, add --insecure or use --cacert ${CERT_DIR}/ca.crt.${RESET}" >&2
  echo -e "${YELLOW}---------------------------------------------------------------${RESET}" >&2
fi

# start uvicorn
uvicorn server:app --host 0.0.0.0 --port 8443 --ssl-keyfile "$CERT_DIR/server.key" --ssl-certfile "$CERT_DIR/server.crt" &
UVICORN_PID=$!

# give the server some time to start
sleep 2

# launch admin GUI in background
python3 "$ROOT/admin_app/main.py" & 
GUI_PID=$!

# trap to cleanup on exit
cleanup() {
  echo "Shutting down..."
  kill "$GUI_PID" 2>/dev/null || true
  kill "$UVICORN_PID" 2>/dev/null || true
}
trap cleanup EXIT

# wait for uvicorn
wait "$UVICORN_PID"
