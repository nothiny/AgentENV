#!/bin/bash
# C1 smoke test: backend selection through the real server and API.
# Run as root inside the dev container (see scripts/dev/container-backend):
#   docker exec yzd-aenv-ct-dev bash /src/scripts/tests/container-backend-c1/smoke.sh
#
# 1. Firecracker-only node: a cold Firecracker sandbox reports backend
#    "firecracker" and still pauses, resumes and deletes; a container request
#    is rejected with 400 backend_not_enabled.
# 2. Node with both backends: container requests for capabilities it lacks
#    are rejected with 400 unsupported_capability before any work, and a
#    plain container request reaches the (not yet implemented) factory.
set -uo pipefail

BASE=/src/scripts/tests/container-backend-c0/c0.toml
SERVER=/target/debug/server
PORT=18000
API=http://127.0.0.1:$PORT
IMAGE=${C1_IMAGE:-docker.io/library/ubuntu:22.04}
LOG=/state/c1-server.log
FAILURES=0
SERVER_PID=

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }

start_server() {
    sed "s/^enabled_backends = .*/enabled_backends = $1/" "$BASE" > /tmp/c1.toml
    mkdir -p /run/yzd-aenv-ct
    AENV_CONFIG_PATH=/tmp/c1.toml API_ADDR=127.0.0.1:$PORT "$SERVER" >> "$LOG" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 240); do
        curl -sf -o /dev/null "$API/health" && break
        kill -0 "$SERVER_PID" 2>/dev/null || { echo "server exited; see $LOG"; exit 1; }
        sleep 0.5
    done
    KEY=$(cat "$AENV_HOME_PATH/secrets/api-key")
    echo "server up with enabled_backends = $1"
}

stop_server() {
    [ -n "$SERVER_PID" ] || return 0
    kill -TERM "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=
}
trap stop_server EXIT

# call METHOD PATH [BODY] -> sets STATUS and BODY_OUT
call() {
    local out
    out=$(curl -s -w '\n%{http_code}' -X "$1" "$API$2" -H "X-API-Key: $KEY" \
        -H 'Content-Type: application/json' ${3:+-d "$3"})
    STATUS=${out##*$'\n'}
    BODY_OUT=${out%$'\n'*}
}

expect() { # expect STATUS [REASON] LABEL
    local want=$1 reason=$2 label=$3
    if [ "$STATUS" != "$want" ]; then
        fail "$label: HTTP $STATUS, want $want: $BODY_OUT"
    elif [ -n "$reason" ] && [ "$(jq -r .reason <<<"$BODY_OUT")" != "$reason" ]; then
        fail "$label: reason $(jq -r .reason <<<"$BODY_OUT"), want $reason"
    else
        pass "$label"
    fi
}

: > "$LOG"

# --- 1. Firecracker-only node -----------------------------------------------
start_server '["firecracker"]'

call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"timeout\":120}"
expect 201 "" "firecracker cold create (backend omitted)"
ID=$(jq -r .sandboxID <<<"$BODY_OUT")
[ "$(jq -r .backend <<<"$BODY_OUT")" = firecracker ] && pass "create reports backend firecracker" \
    || fail "create backend field: $BODY_OUT"

call GET "/sandboxes/$ID"
[ "$(jq -r .backend <<<"$BODY_OUT")" = firecracker ] && pass "detail reports backend firecracker" \
    || fail "detail backend field: $BODY_OUT"
[ "$(jq -r .lifecycle.onTimeout <<<"$BODY_OUT")" = pause ] && pass "omitted autoPause still pauses on Firecracker" \
    || fail "onTimeout: $BODY_OUT"

call POST "/sandboxes/$ID/pause"
expect 204 "" "firecracker pause"
call POST "/sandboxes/$ID/resume" '{"timeout":120}'
expect 201 "" "firecracker resume"
call DELETE "/sandboxes/$ID"
expect 204 "" "firecracker delete"

call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\"}"
expect 400 backend_not_enabled "container rejected on a firecracker-only node"

call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"docker\"}"
# Unknown enum values fail JSON deserialization, like every other enum field.
expect 422 "" "unknown backend name rejected"
stop_server

# --- 2. Node with both backends --------------------------------------------
start_server '["firecracker", "container"]'

for case in '"autoPause":true' '"autoResume":{"enabled":true}' '"extraBootArgs":"x=1"' '"allowInternetAccess":false'; do
    call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\",$case}"
    expect 400 unsupported_capability "container rejects {$case}"
done

call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\"}"
if [ "$STATUS" = 500 ] && grep -q "cannot launch sandboxes yet" <<<"$BODY_OUT"; then
    pass "plain container request reaches the container factory"
else
    fail "plain container request: HTTP $STATUS $BODY_OUT"
fi
call GET /sandboxes
[ "$(jq 'length' <<<"$BODY_OUT")" = 0 ] && pass "failed container create leaves no sandbox" \
    || fail "sandboxes left behind: $BODY_OUT"
stop_server

echo
if [ "$FAILURES" -eq 0 ]; then echo "C1 smoke: all checks passed"; else echo "C1 smoke: $FAILURES check(s) failed"; exit 1; fi
