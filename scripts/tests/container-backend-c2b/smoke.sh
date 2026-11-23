#!/bin/bash
# C2b smoke test: a container-only node starts and serves without KVM, and
# leaves Firecracker's paused sandboxes alone.
# Run as root inside the dev container (see scripts/dev/container-backend),
# after building the server, ublk daemon and CLI (see the C2 smoke test):
#   docker exec yzd-aenv-ct-dev bash /src/scripts/tests/container-backend-c2b/smoke.sh
#
# "No KVM" is simulated by running the server in a private mount namespace
# with a Unix socket file bound over /dev/kvm: the path exists but open()
# fails, so nothing can use KVM. (The rest of /dev must stay live: the ublk
# daemon creates devices in it.)
set -uo pipefail

BASE=/src/scripts/tests/container-backend-c0/c0.toml
SERVER=/target/debug/server
AENV=/target/debug/aenv
PORT=18000
API=http://127.0.0.1:$PORT
IMAGE=${C2B_IMAGE:-docker.io/library/ubuntu:22.04}
FRESH_HOME=/state/c2b-home
LOG=/state/c2b-server.log
FAILURES=0
SERVER_PID=

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }
check() { local label=$1; shift; if "$@"; then pass "$label"; else fail "$label"; fi; }

config() { # enabled_backends value -> /tmp/c2b.toml
    sed "s/^enabled_backends = .*/enabled_backends = $1/" "$BASE" > /tmp/c2b.toml
}

# start_server HOME MASK_KVM(yes|no) -> 0 when the API comes up
start_server() {
    local home=$1 mask=$2
    mkdir -p /run/yzd-aenv-ct "$home"
    local run="AENV_HOME_PATH=$home AENV_CONFIG_PATH=/tmp/c2b.toml API_ADDR=127.0.0.1:$PORT exec $SERVER"
    if [ "$mask" = yes ]; then
        local mask=/tmp/c2b-kvm-mask.sock
        rm -rf "$mask"
        python3 -c "import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])" "$mask"
        unshare -m --propagation private sh -c \
            "mount --bind $mask /dev/kvm && ! head -c1 /dev/kvm 2>/dev/null && $run" >> "$LOG" 2>&1 &
    else
        sh -c "$run" >> "$LOG" 2>&1 &
    fi
    SERVER_PID=$!
    for _ in $(seq 1 600); do
        curl -sf -o /dev/null "$API/health" && break
        kill -0 "$SERVER_PID" 2>/dev/null || { SERVER_PID=; return 1; }
        sleep 0.5
    done
    KEY=$(cat "$home/secrets/api-key")
    mkdir -p /root/.config/aenv
    printf 'url = "%s"\napi_key = "%s"\n' "$API" "$KEY" > /root/.config/aenv/credentials
}

stop_server() {
    [ -n "$SERVER_PID" ] || return 0
    kill -TERM "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=
}
trap stop_server EXIT

call() {
    local out
    out=$(curl -s -w '\n%{http_code}' -X "$1" "$API$2" -H "X-API-Key: $KEY" \
        -H 'Content-Type: application/json' ${3:+-d "$3"})
    STATUS=${out##*$'\n'}
    BODY_OUT=${out%$'\n'*}
}
status_reason() { echo "$STATUS/$(jq -r .reason <<<"$BODY_OUT")"; }

: > "$LOG"
rm -rf "$FRESH_HOME"

# --- 1. negative control: Firecracker needs /dev/kvm --------------------------
config '["firecracker"]'
if start_server "$FRESH_HOME" yes; then
    fail "firecracker-only node should not start without a usable /dev/kvm"
    stop_server
else
    pass "firecracker-only node refuses to start without a usable /dev/kvm"
fi
rm -rf "$FRESH_HOME"

# --- 2. container-only node on a fresh home without /dev/kvm ------------------
config '["container"]'
if start_server "$FRESH_HOME" yes; then pass "container-only node starts without a usable /dev/kvm"; else
    fail "container-only node did not start"; tail -20 "$LOG"; exit 1; fi
check "no firecracker binary downloaded" test ! -e "$FRESH_HOME/deps/firecracker"
check "no guest kernel downloaded" test ! -e "$FRESH_HOME/deps/kernel"

call POST /sandboxes-cold "{\"image\":\"$IMAGE\"}"
check "omitted backend is rejected (firecracker not enabled)" test "$(status_reason)" = "400/backend_not_enabled"

call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\",\"timeout\":120}"
check "container sandbox starts" test "$STATUS" = 201
ID=$(jq -r .sandboxID <<<"$BODY_OUT")
OUT=$("$AENV" exec "$ID" -- sh -c 'head -1 /etc/os-release' 2>&1)
check "exec works" grep -q Ubuntu <<<"$OUT"

call POST /v2/templates/x/builds/x '{}'
check "template builds are rejected (firecracker not enabled)" test "$(status_reason)" = "400/backend_not_enabled"

call DELETE "/sandboxes/$ID"
check "delete" test "$STATUS" = 204
stop_server

# --- 3. paused Firecracker sandboxes survive a container-only start ---------
config '["firecracker", "container"]'
start_server "$AENV_HOME_PATH" no || { fail "firecracker node did not start"; exit 1; }
call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"timeout\":600}"
FC_ID=$(jq -r .sandboxID <<<"$BODY_OUT")
"$AENV" exec "$FC_ID" -- sh -c 'echo keep-me > /root/marker' >/dev/null 2>&1
call POST "/sandboxes/$FC_ID/pause"
check "firecracker sandbox paused" test "$STATUS" = 204
stop_server

config '["container"]'
start_server "$AENV_HOME_PATH" yes || { fail "container-only node did not start on the same home"; exit 1; }
call GET "/sandboxes/$FC_ID"
check "paused firecracker sandbox is still listed" test "$STATUS/$(jq -r .state <<<"$BODY_OUT")" = "200/paused"
call POST "/sandboxes/$FC_ID/resume" '{"timeout":600}'
check "resume is rejected with backend_not_enabled" test "$(status_reason)" = "400/backend_not_enabled"
stop_server

config '["firecracker", "container"]'
start_server "$AENV_HOME_PATH" no || { fail "firecracker node did not restart"; exit 1; }
call POST "/sandboxes/$FC_ID/resume" '{"timeout":600}'
check "firecracker node resumes the sandbox" test "$STATUS" = 201
OUT=$("$AENV" exec "$FC_ID" -- cat /root/marker 2>&1)
check "its state survived" grep -qx keep-me <<<"$OUT"
call DELETE "/sandboxes/$FC_ID"
check "delete" test "$STATUS" = 204
stop_server

echo
if [ "$FAILURES" -eq 0 ]; then echo "C2b smoke: all checks passed"; else echo "C2b smoke: $FAILURES check(s) failed"; exit 1; fi
