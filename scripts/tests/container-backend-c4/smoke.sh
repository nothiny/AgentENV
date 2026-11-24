#!/bin/bash
# C4 smoke test: root filesystem images and filesystem-only forks of
# container sandboxes, and images shared with Firecracker.
# Run as root inside the dev container after building the server, ublk daemon
# and CLI (see the C2 smoke test):
#   docker exec yzd-aenv-ct-dev bash /src/scripts/tests/container-backend-c4/smoke.sh
set -uo pipefail

BASE=/src/scripts/tests/container-backend-c0/c0.toml
SERVER=/target/debug/server
AENV=/target/debug/aenv
PORT=18000
API=http://127.0.0.1:$PORT
IMAGE=${C4_IMAGE:-docker.io/library/ubuntu:22.04}
LOG=/state/c4-server.log
NAME=c4-img-$$
LAYERS=$AENV_HOME_PATH/container/layers
FAILURES=0
SERVER_PID=

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }
check() { local label=$1; shift; if "$@"; then pass "$label"; else fail "$label"; fi; }

start_server() {
    sed 's/^enabled_backends = .*/enabled_backends = ["firecracker", "container"]/' "$BASE" > /tmp/c4.toml
    mkdir -p /run/yzd-aenv-ct
    AENV_CONFIG_PATH=/tmp/c4.toml API_ADDR=127.0.0.1:$PORT "$SERVER" >> "$LOG" 2>&1 &
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
create() { # image backend -> ID
    call POST /sandboxes-cold "{\"image\":\"$1\",\"backend\":\"$2\",\"timeout\":300}"
    ID=$(jq -r .sandboxID <<<"$BODY_OUT")
    [ "$STATUS" = 201 ]
}
in_box() { "$AENV" exec "$1" -- sh -c "$2" 2>&1; }
layer_dirs() { find "$LAYERS" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l; }

: > "$LOG"
start_server

# --- capture a root filesystem image ------------------------------------------
check "source container" create "$IMAGE" container
A=$ID
in_box "$A" 'mkdir -p /opt/app && echo from-template > /opt/app/hello && echo before > /root/state' >/dev/null
START=$(date +%s%N)
call POST "/sandboxes/$A/snapshots" "{\"name\":\"$NAME\"}"
ELAPSED_MS=$(( ($(date +%s%N) - START) / 1000000 ))
check "snapshot publishes an image (${ELAPSED_MS} ms)" test "$STATUS" = 201
REF=$(jq -r .imageRef <<<"$BODY_OUT")
DIGEST=$(jq -r .snapshotID <<<"$BODY_OUT")
check "response names aenv/$NAME:latest" test "$REF" = "aenv/$NAME:latest"
check "snapshot ID is the image digest" grep -q '^sha256:' <<<"$DIGEST"
check "source keeps running after the snapshot" test "$(in_box "$A" 'cat /root/state')" = before
in_box "$A" 'echo after > /root/state' >/dev/null

# --- launch the image on both backends ----------------------------------------
check "container from the image" create "$REF" container
B=$ID
check "it has the template's files" test "$(in_box "$B" 'cat /opt/app/hello')" = from-template
check "and not writes made after the snapshot" test "$(in_box "$B" 'cat /root/state')" = before

check "firecracker sandbox from the same image" create "$REF" firecracker
F=$ID
check "firecracker sees the template's files" test "$(in_box "$F" 'cat /opt/app/hello')" = from-template

check "container from the digest" create "$DIGEST" container
D=$ID
check "the digest names the same image" test "$(in_box "$D" 'cat /opt/app/hello')" = from-template

# --- filesystem-only fork -----------------------------------------------------
"$AENV" exec "$A" -- sh -c 'sleep 600 >/dev/null 2>&1 &' >/dev/null 2>&1
START=$(date +%s%N)
call POST "/sandboxes/$A/fork" '{"count":2}'
ELAPSED_MS=$(( ($(date +%s%N) - START) / 1000000 ))
check "fork into two children (${ELAPSED_MS} ms)" test "$STATUS" = 201
mapfile -t KIDS < <(jq -r '.[].sandbox.sandboxID // empty' <<<"$BODY_OUT")
check "two children started" test "${#KIDS[@]}" = 2
C1=${KIDS[0]:-none}; C2=${KIDS[1]:-none}
check "children inherit the parent's files" test "$(in_box "$C1" 'cat /root/state')" = after
check "children start fresh processes" test "$(in_box "$C1" 'pgrep -c sleep || true')" = 0
in_box "$C1" 'echo child1 > /root/state' >/dev/null
check "a child's writes stay out of its sibling" test "$(in_box "$C2" 'cat /root/state')" = after
check "and out of the parent" test "$(in_box "$A" 'cat /root/state')" = after
call GET "/sandboxes/$C1"
check "children are container sandboxes" test "$(jq -r .backend <<<"$BODY_OUT")" = container

call DELETE "/sandboxes/$A"
check "delete the parent" test "$STATUS" = 204
check "children keep working without the parent" test "$(in_box "$C2" 'cat /opt/app/hello')" = from-template
check "sealed layers kept while children use them" test "$(layer_dirs)" -ge 1
for id in "$C1" "$C2" "$B" "$F" "$D"; do call DELETE "/sandboxes/$id"; done
check "last delete removes the sealed layers" test "$(layer_dirs)" = 0
check "no container mounts left" test "$(grep -c "/container/sandboxes/" /proc/self/mountinfo)" = 0
stop_server

echo
if [ "$FAILURES" -eq 0 ]; then echo "C4 smoke: all checks passed"; else echo "C4 smoke: $FAILURES check(s) failed"; exit 1; fi
