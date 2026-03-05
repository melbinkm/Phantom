#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# reset-server.sh — Programmatically reset phantom-bench via Hetzner Robot API.
#
# Usage:
#   ./scripts/reset-server.sh              # hardware reset (default)
#   ./scripts/reset-server.sh --check      # check server status only
#   ./scripts/reset-server.sh --type sw    # software reset (CTRL+ALT+DEL)
#   ./scripts/reset-server.sh --type hw    # hardware reset (power cycle)
#   ./scripts/reset-server.sh --type man   # manual reset request to DC
#
# The script will:
#   1. Verify the server is actually unreachable (3 ping + 1 SSH check)
#   2. Trigger the reset via Hetzner Robot API
#   3. Wait for the server to come back online
#   4. Report success/failure

set -euo pipefail

SERVER_IP="95.217.47.28"
CREDS_FILE="$(dirname "$0")/../.secret/hetzner_creds"
API_BASE="https://robot-ws.your-server.de"
RESET_TYPE="${RESET_TYPE:-hw}"
CHECK_ONLY=false

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)    CHECK_ONLY=true ;;
        --type)     RESET_TYPE="$2"; shift ;;
        --help|-h)
            sed -n '3,15p' "$0" | sed 's/^# //'
            exit 0 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
    shift
done

# Read credentials
if [[ ! -f "$CREDS_FILE" ]]; then
    echo "ERROR: credentials not found at $CREDS_FILE" >&2
    exit 1
fi
CREDS=$(cat "$CREDS_FILE")

api_call() {
    local method="$1" endpoint="$2"
    shift 2
    python3 - "$method" "$endpoint" "$CREDS" "$@" << 'PYEOF'
import sys, urllib.request, urllib.error, urllib.parse, base64, json

method, endpoint, creds = sys.argv[1], sys.argv[2], sys.argv[3]
extra = sys.argv[4:]

user, pwd = creds.split(':', 1)
token = base64.b64encode(f'{user}:{pwd}'.encode()).decode()

url = f"https://robot-ws.your-server.de{endpoint}"
data = urllib.parse.urlencode(dict(x.split('=',1) for x in extra)).encode() if extra else None

req = urllib.request.Request(url, data=data, method=method,
    headers={'Authorization': f'Basic {token}',
             'Content-Type': 'application/x-www-form-urlencoded'})
try:
    with urllib.request.urlopen(req, timeout=15) as r:
        print(r.read().decode())
except urllib.error.HTTPError as e:
    print(json.dumps({"error": {"status": e.code, "body": e.read().decode()}}))
    sys.exit(1)
PYEOF
}

# Check current server status
echo "=== phantom-bench reset script ==="
echo "Server: $SERVER_IP"

echo ""
echo "Checking server reachability..."
PING_OK=false
SSH_OK=false

if ping -c 3 -W 2 "$SERVER_IP" &>/dev/null; then
    PING_OK=true
    echo "  ping:  OK"
else
    echo "  ping:  FAIL (no response)"
fi

if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
       -o BatchMode=yes phantom-bench "exit 0" &>/dev/null 2>&1; then
    SSH_OK=true
    echo "  ssh:   OK"
else
    echo "  ssh:   FAIL (not responding)"
fi

if $CHECK_ONLY; then
    echo ""
    echo "Status: ping=$PING_OK ssh=$SSH_OK"
    exit 0
fi

# Safety check — don't reset a reachable server
if $SSH_OK; then
    echo ""
    echo "ERROR: Server is reachable via SSH — reset aborted." >&2
    echo "Only reset when the server is genuinely unresponsive (>10 min)." >&2
    exit 1
fi

# Trigger reset
echo ""
echo "Server unreachable. Triggering $RESET_TYPE reset via Hetzner API..."
RESULT=$(api_call POST "/reset/$SERVER_IP" "type=$RESET_TYPE")
echo "API response: $RESULT"

if echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if 'reset' in d else 1)" 2>/dev/null; then
    echo "Reset triggered successfully."
else
    echo "ERROR: Reset may have failed — check response above." >&2
    exit 1
fi

# Wait for server to come back
echo ""
echo "Waiting for server to come back online (up to 5 minutes)..."
DEADLINE=$((SECONDS + 300))
while [[ $SECONDS -lt $DEADLINE ]]; do
    sleep 10
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
           -o BatchMode=yes phantom-bench "exit 0" &>/dev/null 2>&1; then
        echo "Server is back online!"
        echo ""
        ssh phantom-bench "uname -r && uptime"
        exit 0
    fi
    printf "."
done

echo ""
echo "WARNING: Server did not come back within 5 minutes." >&2
echo "Check Hetzner Robot panel: https://robot.hetzner.com" >&2
exit 1
