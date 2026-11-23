#!/bin/bash
# C2 smoke test: container sandboxes through the real server, API and CLI.
# Run as root inside the dev container (see scripts/dev/container-backend),
# after building the server, ublk daemon and CLI:
#   cargo build -p agentenv --bin server -p uvm-ublk-daemon --bin uvm-ublk-daemon
#   cargo build -p aenv
#   docker exec yzd-aenv-ct-dev bash /src/scripts/tests/container-backend-c2/smoke.sh
set -uo pipefail

BASE=/src/scripts/tests/container-backend-c0/c0.toml
SERVER=/target/debug/server
AENV=/target/debug/aenv
PORT=18000
API=http://127.0.0.1:$PORT
IMAGE=${C2_IMAGE:-docker.io/library/ubuntu:22.04}
LOG=/state/c2-server.log
WORK_BASE=$AENV_HOME_PATH/container/sandboxes
FAILURES=0
SERVER_PID=

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }
check() { local label=$1; shift; if "$@"; then pass "$label"; else fail "$label"; fi; }

start_server() {
    sed 's/^enabled_backends = .*/enabled_backends = ["firecracker", "container"]/' "$BASE" > /tmp/c2.toml
    mkdir -p /run/yzd-aenv-ct
    AENV_CONFIG_PATH=/tmp/c2.toml API_ADDR=127.0.0.1:$PORT "$SERVER" >> "$LOG" 2>&1 &
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

stop_server() { # $1 = signal
    [ -n "$SERVER_PID" ] || return 0
    kill "-${1:-TERM}" "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=
}
trap 'stop_server TERM' EXIT

call() {
    local out
    out=$(curl -s -w '\n%{http_code}' -X "$1" "$API$2" -H "X-API-Key: $KEY" \
        -H 'Content-Type: application/json' ${3:+-d "$3"})
    STATUS=${out##*$'\n'}
    BODY_OUT=${out%$'\n'*}
}

create() { # create JSON-fields -> ID
    call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\"$1}"
    ID=$(jq -r .sandboxID <<<"$BODY_OUT")
}

runtime_containers() { runc --root /run/yzd-aenv-ct/container/runtime list -q 2>/dev/null | grep -c '^aenv-'; }
container_mounts() { grep -c " $WORK_BASE/" /proc/self/mountinfo; }
work_dirs() { find "$WORK_BASE" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l; }
nothing_left() {
    [ "$(runtime_containers)" = 0 ] && [ "$(container_mounts)" = 0 ] && [ "$(work_dirs)" = 0 ]
}

: > "$LOG"
UBLK_BEFORE=$(ls /dev/ublkb* 2>/dev/null | wc -l)
start_server

# --- create ------------------------------------------------------------------
START=$(date +%s%N)
create ',"timeout":300,"cpuCount":2,"memoryMB":1024'
ELAPSED_MS=$(( ($(date +%s%N) - START) / 1000000 ))
if [ "$STATUS" = 201 ]; then pass "container cold create (${ELAPSED_MS} ms incl. image resolve)"; else
    fail "container cold create: HTTP $STATUS $BODY_OUT"; echo "server log tail:"; tail -20 "$LOG"; exit 1; fi
check "create reports backend container" test "$(jq -r .backend <<<"$BODY_OUT")" = container
call GET "/sandboxes/$ID"
check "detail: backend container" test "$(jq -r .backend <<<"$BODY_OUT")" = container
check "detail: omitted autoPause kills on timeout" test "$(jq -r .lifecycle.onTimeout <<<"$BODY_OUT")" = kill
check "one runtime container" test "$(runtime_containers)" = 1
UBLK_RUNNING=$(ls /dev/ublkb* 2>/dev/null | wc -l)

# --- exec --------------------------------------------------------------------
OUT=$("$AENV" exec "$ID" -- sh -c 'head -1 /etc/os-release; id -u; hostname' 2>&1)
check "exec runs in the image" grep -q 'Ubuntu' <<<"$OUT"
check "exec runs as root by default" grep -qx '0' <<<"$OUT"
OUT=$("$AENV" exec "$ID" -- sh -c 'cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max' 2>&1)
check "memory limit 1024 MiB" grep -qx '1073741824' <<<"$OUT"
check "cpu limit 2 cores" grep -qx '200000 100000' <<<"$OUT"
OUT=$("$AENV" exec "$ID" -- sh -c 'exit 7' 2>&1); CODE=$?
check "exit code propagates" test "$CODE" = 7
OUT=$("$AENV" exec "$ID" -- /agentenv/bin/busybox wget -q -T 10 -O- http://example.com 2>&1)
check "outbound HTTP works" grep -qi '<html' <<<"$OUT"

# --- files -------------------------------------------------------------------
head -c 1048576 /dev/urandom > /tmp/c2-upload.bin
"$AENV" upload "$ID" /tmp/c2-upload.bin /tmp/c2-upload.bin >/dev/null 2>&1
rm -f /tmp/c2-download.bin
"$AENV" download "$ID" /tmp/c2-upload.bin /tmp/c2-download.bin >/dev/null 2>&1
check "upload/download round trip (1 MiB)" cmp -s /tmp/c2-upload.bin /tmp/c2-download.bin

# --- unsupported operations leave the sandbox running -------------------------
call POST "/sandboxes/$ID/pause"
check "pause rejected with 400 unsupported_capability" \
    test "$STATUS/$(jq -r .reason <<<"$BODY_OUT")" = "400/unsupported_capability"
OUT=$("$AENV" exec "$ID" -- echo still-running 2>&1)
check "sandbox still serves exec after rejected pause" grep -qx still-running <<<"$OUT"

# --- delete ------------------------------------------------------------------
call DELETE "/sandboxes/$ID"
check "delete returns 204" test "$STATUS" = 204
check "delete releases container, mounts and work dir" nothing_left
# The shared tools drive stays attached for the next sandbox; the rootfs goes.
check "delete releases the rootfs device" test "$(ls /dev/ublkb* 2>/dev/null | wc -l)" = "$((UBLK_RUNNING - 1))"

# --- TTL expiry deletes ------------------------------------------------------
create ',"timeout":3'
check "short-lived create" test "$STATUS" = 201
for _ in $(seq 1 30); do call GET "/sandboxes/$ID"; [ "$STATUS" = 404 ] && break; sleep 1; done
check "expired container sandbox is deleted" test "$STATUS" = 404
check "expiry releases everything" nothing_left

# --- crash and restart -------------------------------------------------------
create ',"timeout":300'
check "create before crash" test "$STATUS" = 201
stop_server KILL
check "container outlives a killed server" test "$(runtime_containers)" = 1
start_server
check "restart removes leftover container, mounts and work dir" nothing_left
call GET "/sandboxes/$ID"
check "leftover sandbox is not reported after restart" test "$STATUS" = 404
stop_server TERM
for _ in $(seq 1 20); do [ "$(ls /dev/ublkb* 2>/dev/null | wc -l)" = "$UBLK_BEFORE" ] && break; sleep 0.5; done
UBLK_AFTER=$(ls /dev/ublkb* 2>/dev/null | wc -l)
[ "$UBLK_AFTER" = "$UBLK_BEFORE" ] && pass "no ublk devices left after shutdown" \
    || echo "NOTE  ublk devices: $UBLK_BEFORE before, $UBLK_AFTER after (a crashed run's devices are released by the next daemon sweep)"

echo
if [ "$FAILURES" -eq 0 ]; then echo "C2 smoke: all checks passed"; else echo "C2 smoke: $FAILURES check(s) failed"; exit 1; fi
