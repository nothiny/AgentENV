#!/bin/bash
# C3 network smoke test: egress rules and network updates on container
# sandboxes, checked with real traffic.
# Run as root inside the dev container after building the server, ublk daemon
# and CLI (see the C2 smoke test):
#   docker exec yzd-aenv-ct-dev bash /src/scripts/tests/container-backend-c3/network.sh
set -uo pipefail

BASE=/src/scripts/tests/container-backend-c0/c0.toml
SERVER=/target/debug/server
AENV=/target/debug/aenv
PORT=18000
API=http://127.0.0.1:$PORT
IMAGE=${C3_IMAGE:-docker.io/library/ubuntu:22.04}
LOG=/state/c3-network-server.log
BB=/agentenv/bin/busybox
ALLOWED_URL=http://example.com
BLOCKED_URL=http://1.1.1.1
FAILURES=0
SERVER_PID=

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }
check() { local label=$1; shift; if "$@"; then pass "$label"; else fail "$label"; fi; }

start_server() {
    sed 's/^enabled_backends = .*/enabled_backends = ["container"]/' "$BASE" > /tmp/c3.toml
    mkdir -p /run/yzd-aenv-ct
    AENV_CONFIG_PATH=/tmp/c3.toml API_ADDR=127.0.0.1:$PORT "$SERVER" >> "$LOG" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 240); do
        curl -sf -o /dev/null "$API/health" && break
        kill -0 "$SERVER_PID" 2>/dev/null || { echo "server exited; see $LOG"; exit 1; }
        sleep 0.5
    done
    KEY=$(cat "$AENV_HOME_PATH/secrets/api-key")
    mkdir -p /root/.config/aenv
    printf 'url = "%s"\napi_key = "%s"\n' "$API" "$KEY" > /root/.config/aenv/credentials
}
stop_server() { [ -n "$SERVER_PID" ] && kill -TERM "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null; SERVER_PID=; }
trap stop_server EXIT

call() {
    local out
    out=$(curl -s -w '\n%{http_code}' -X "$1" "$API$2" -H "X-API-Key: $KEY" \
        -H 'Content-Type: application/json' ${3:+-d "$3"})
    STATUS=${out##*$'\n'}
    BODY_OUT=${out%$'\n'*}
}
create() { # extra JSON fields -> ID
    call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\",\"timeout\":300$1}"
    [ "$STATUS" = 201 ] || { fail "create $1: HTTP $STATUS $BODY_OUT"; return 1; }
    ID=$(jq -r .sandboxID <<<"$BODY_OUT")
}
# reaches SANDBOX URL -> 0 when an HTTP response arrives
reaches() { "$AENV" exec "$1" -- $BB wget -q -T 5 -O /dev/null "$2" >/dev/null 2>&1; }
blocked() { ! reaches "$@"; }

: > "$LOG"
start_server

# --- create with internet access disabled ------------------------------------
create ',"allowInternetAccess":false' || exit 1
A=$ID
call GET "/sandboxes/$A"
check "detail reports internet access disabled" test "$(jq -r .allowInternetAccess <<<"$BODY_OUT")" = false
check "egress blocked when allowInternetAccess=false" blocked "$A" "$ALLOWED_URL"
check "exec and envd still work" test "$("$AENV" exec "$A" -- echo ok 2>/dev/null)" = ok

# --- update: allow everything --------------------------------------------------
call PUT "/sandboxes/$A/network" '{"allow_internet_access":true}'
check "network update accepted" test "$STATUS" = 204
check "egress works after allowing internet access" reaches "$A" "$ALLOWED_URL"
CONTROL_OK=0
reaches "$A" "$BLOCKED_URL" && CONTROL_OK=1

# --- update: deny all but one domain (egress proxy) ---------------------------
call PUT "/sandboxes/$A/network" '{"denyOut":["0.0.0.0/0"],"allowOut":["example.com"]}'
check "domain allowlist accepted" test "$STATUS" = 204
check "allowed domain is reachable through the egress proxy" reaches "$A" "$ALLOWED_URL"
if [ "$CONTROL_OK" = 1 ]; then
    check "other destinations are blocked" blocked "$A" "$BLOCKED_URL"
else
    echo "SKIP  other destinations are blocked ($BLOCKED_URL is unreachable from this host anyway)"
fi

# --- isolation from other sandboxes -------------------------------------------
call PUT "/sandboxes/$A/network" '{"allow_internet_access":true}'
create '' || exit 1
B=$ID
# Every slot's host interaction address, including warm-pool slots and B's.
mapfile -t HOST_IPS < <(ip -4 route show | awk '/ dev veth-/ && $1 !~ /\// {print $1}')
check "found host interaction addresses for both sandboxes" test "${#HOST_IPS[@]}" -ge 2
for ip in "${HOST_IPS[@]}"; do
    check "sandbox cannot reach envd at $ip" blocked "$A" "http://$ip:49983/health"
done

call DELETE "/sandboxes/$A"; check "delete A" test "$STATUS" = 204
call DELETE "/sandboxes/$B"; check "delete B" test "$STATUS" = 204
stop_server

echo
if [ "$FAILURES" -eq 0 ]; then echo "C3 network smoke: all checks passed"; else echo "C3 network smoke: $FAILURES check(s) failed"; exit 1; fi
