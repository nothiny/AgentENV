#!/bin/bash
# C3 drives smoke test: managed volumes and attached drives in container
# sandboxes, and volumes shared with Firecracker.
# Run as root inside the dev container after building the server, ublk daemon
# and CLI (see the C2 smoke test):
#   docker exec yzd-aenv-ct-dev bash /src/scripts/tests/container-backend-c3/drives.sh
set -uo pipefail

BASE=/src/scripts/tests/container-backend-c0/c0.toml
SERVER=/target/debug/server
AENV=/target/debug/aenv
PORT=18000
API=http://127.0.0.1:$PORT
IMAGE=${C3_IMAGE:-docker.io/library/ubuntu:22.04}
DRIVE_IMAGE=${C3_DRIVE_IMAGE:-docker.io/library/alpine:3.19}
LOG=/state/c3-drives-server.log
VOLUME=c3vol-$$
FAILURES=0
SERVER_PID=

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }
check() { local label=$1; shift; if "$@"; then pass "$label"; else fail "$label"; fi; }

start_server() {
    sed 's/^enabled_backends = .*/enabled_backends = ["firecracker", "container"]/' "$BASE" > /tmp/c3.toml
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
create() { # backend extra-json -> ID
    call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"$1\",\"timeout\":300$2}"
    ID=$(jq -r .sandboxID <<<"$BODY_OUT")
    [ "$STATUS" = 201 ]
}
in_box() { "$AENV" exec "$1" -- sh -c "$2" 2>&1; }

: > "$LOG"
start_server
MOUNT=",\"volumeMounts\":[{\"name\":\"$VOLUME\",\"path\":\"/data\"}]"

call POST /volumes "{\"name\":\"$VOLUME\",\"sizeMB\":1024}"
check "create volume" test "$STATUS" = 201

# --- write in one container, read in the next --------------------------------
check "container with the volume mounted" create container "$MOUNT"
A=$ID
OUT=$(in_box "$A" 'echo written-by-container > /data/hello && cat /data/hello && df -h /data | tail -1')
check "write to the volume" grep -q written-by-container <<<"$OUT"
echo "      $(tail -1 <<<"$OUT")"

create container "$MOUNT"
check "an exclusive volume cannot be mounted twice (HTTP $STATUS)" test "$STATUS" = 409

# Forking copies the volume: the child gets its own copy-on-write volume
# with the parent's data, sealed through the container's volume snapshot.
call POST "/sandboxes/$A/fork" '{"count":1}'
check "fork a container with a volume" test "$STATUS" = 201
K=$(jq -r '.[0].sandbox.sandboxID // empty' <<<"$BODY_OUT")
check "the child sees the parent's volume data" test "$(in_box "$K" 'cat /data/hello')" = written-by-container
in_box "$K" 'echo child > /data/hello' >/dev/null
check "the child's volume writes stay out of the parent" \
    test "$(in_box "$A" 'cat /data/hello')" = written-by-container
call DELETE "/sandboxes/$K"; check "delete the fork child" test "$STATUS" = 204

call DELETE "/sandboxes/$A"
check "delete seals the volume" test "$STATUS" = 204

check "second container mounts the volume" create container "$MOUNT"
B=$ID
check "data survives across containers" test "$(in_box "$B" 'cat /data/hello')" = written-by-container
call DELETE "/sandboxes/$B"; check "delete second container" test "$STATUS" = 204

# --- same volume in Firecracker -----------------------------------------------
check "firecracker sandbox mounts the same volume" create firecracker "$MOUNT"
F=$ID
check "firecracker reads what the container wrote" \
    test "$(in_box "$F" 'cat /data/hello')" = written-by-container
in_box "$F" 'echo written-by-vm >> /data/hello' >/dev/null
call DELETE "/sandboxes/$F"; check "delete firecracker sandbox" test "$STATUS" = 204
check "container mounts it again" create container "$MOUNT"
C=$ID
check "container reads what the VM appended" \
    test "$(in_box "$C" 'tail -1 /data/hello')" = written-by-vm
call DELETE "/sandboxes/$C"; check "delete" test "$STATUS" = 204

# --- read-only attached drive -------------------------------------------------
DRIVE=",\"attachedDrives\":[{\"driveID\":\"alpine\",\"source\":{\"image\":\"$DRIVE_IMAGE\"},\"mountPath\":\"/mnt/alpine\",\"readOnly\":true}]"
check "container with a read-only attached drive" create container "$DRIVE"
D=$ID
check "attached drive content is visible" grep -q '^3\.19' <<<"$(in_box "$D" 'cat /mnt/alpine/etc/alpine-release')"
OUT=$(in_box "$D" 'touch /mnt/alpine/x && echo wrote || echo refused')
check "attached drive is read-only" grep -qx refused <<<"$OUT"
call DELETE "/sandboxes/$D"; check "delete" test "$STATUS" = 204

call DELETE "/volumes/$VOLUME"
check "delete volume (HTTP $STATUS)" test "$STATUS" = 204
check "no drive mounts left" test "$(grep -c "/container/sandboxes/.*/drives/" /proc/self/mountinfo)" = 0
stop_server

echo
if [ "$FAILURES" -eq 0 ]; then echo "C3 drives smoke: all checks passed"; else echo "C3 drives smoke: $FAILURES check(s) failed"; exit 1; fi
