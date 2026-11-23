#!/bin/bash
# C3 guest smoke test: metrics and logs of container sandboxes, and reaping of
# orphaned processes inside them.
# Run as root inside the dev container after building the server, ublk daemon
# and CLI (see the C2 smoke test):
#   docker exec yzd-aenv-ct-dev bash /src/scripts/tests/container-backend-c3/guest.sh
set -uo pipefail

BASE=/src/scripts/tests/container-backend-c0/c0.toml
SERVER=/target/debug/server
AENV=/target/debug/aenv
PORT=18000
API=http://127.0.0.1:$PORT
IMAGE=${C3_IMAGE:-docker.io/library/ubuntu:22.04}
LOG=/state/c3-guest-server.log
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
metric() { jq -r "if type == \"array\" then .[-1] else . end | .$1" <<<"$BODY_OUT"; }
# Samples come from the orchestrator's periodic collector; wait for one taken
# at or after unix time $1.
sample_after() {
    for _ in $(seq 1 60); do
        call GET "/sandboxes/$ID/metrics"
        [ "$STATUS" = 200 ] && [ "$(metric timestampUnix)" != null ] \
            && [ "$(metric timestampUnix)" -ge "$1" ] && return 0
        sleep 1
    done
    return 1
}

: > "$LOG"
start_server
call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\",\"timeout\":300,\"cpuCount\":2,\"memoryMB\":512}"
check "create" test "$STATUS" = 201
ID=$(jq -r .sandboxID <<<"$BODY_OUT")

# --- metrics ------------------------------------------------------------------
check "a metrics sample is collected" sample_after "$(date +%s)"
echo "      idle sample: $(jq -c 'if type == "array" then .[-1] else . end' <<<"$BODY_OUT")"
check "memTotal is the 512 MiB limit" test "$(metric memTotal)" = $((512 * 1024 * 1024))
check "cpuCount is the 2-core quota" test "$(metric cpuCount)" = 2
check "memUsed is the container's, well under the limit" \
    test "$(metric memUsed)" -lt $((512 * 1024 * 1024))
check "diskTotal is the rootfs size (> 1 GiB)" test "$(metric diskTotal)" -gt $((1024 * 1024 * 1024))

"$AENV" exec "$ID" -- sh -c 'timeout 30 sh -c "while :; do :; done" >/dev/null 2>&1 &' >/dev/null 2>&1
sleep 2
check "a sample is collected under load" sample_after "$(( $(date +%s) + 1 ))"
BUSY=$(metric cpuUsedPct)
echo "      busy sample: cpuUsedPct=$BUSY"
check "one busy core shows about 50% of a 2-core quota" \
    awk -v v="$BUSY" 'BEGIN { exit !(v >= 30 && v <= 70) }'

# --- logs ---------------------------------------------------------------------
call GET "/v2/sandboxes/$ID/logs?limit=200"
check "logs endpoint" test "$STATUS" = 200
check "logs contain envd process events" grep -q "Process with pid" <<<"$BODY_OUT"

# --- reaping of orphans inside the container ----------------------------------
"$AENV" exec "$ID" -- sh -c '(sleep 1 &); true' >/dev/null 2>&1
sleep 3
ZOMBIES=$("$AENV" exec "$ID" -- sh -c "ps -eo stat= | grep -c '^Z' || true" 2>/dev/null)
check "orphaned processes are reaped (zombies: ${ZOMBIES:-?})" test "${ZOMBIES:-1}" = 0
PID1=$("$AENV" exec "$ID" -- sh -c "tr '\\0' ' ' < /proc/1/cmdline" 2>/dev/null)
check "PID 1 is busybox init (got ${PID1:-?})" test "$PID1" = "/agentenv/bin/busybox init "

# envd is supervised: if it dies, init starts it again.
"$AENV" exec "$ID" -- sh -c 'kill -9 $(pidof envd)' >/dev/null 2>&1
sleep 2
ENVD_AFTER=$(pgrep -x envd | sort | tr '\n' ' ')
check "envd is restarted after it dies" \
    test -n "$ENVD_AFTER"

call DELETE "/sandboxes/$ID"
check "delete" test "$STATUS" = 204
stop_server

echo
if [ "$FAILURES" -eq 0 ]; then echo "C3 guest smoke: all checks passed"; else echo "C3 guest smoke: $FAILURES check(s) failed"; exit 1; fi
