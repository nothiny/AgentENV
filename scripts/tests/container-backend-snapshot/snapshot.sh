#!/bin/bash
# Memory snapshots of container sandboxes: the processes, rootfs and volumes
# are captured in one frozen window and stored as a snapshot; sandboxes
# launched from it restore the processes as new containers.
#
#   1. A secure source with a volume is snapshotted and keeps running; no
#      capture is left behind.
#   2. A secure launch from the snapshot runs the source's process (same PID,
#      counting on), has the rootfs and volume as captured (not the source's
#      later writes), and its envd takes only its own token.
#   3. A non-secure launch from the same snapshot works without a token.
#   4. The snapshot outlives its source.
#   5. A launch that mounts other volumes is refused.
#
# Needs a debug build, criu, and a tools image with the access-token-hash-file
# envd patch. Run as root inside the dev container after building the server,
# ublk daemon and CLI, e.g. with a patched tools image imported as an OCI
# layout:
#   docker exec -e SNAP_TOOLS_VERSION=0.1.2-dev.3 \
#     -e 'SNAP_TOOLS_URL=ocidir:///state/tools-oci:{version}' \
#     yzd-aenv-ct-dev bash /src/scripts/tests/container-backend-snapshot/snapshot.sh
# SNAP_RUNTIME=crun runs it under crun (default runc).
set -uo pipefail

BASE=/src/scripts/tests/container-backend-c0/c0.toml
SERVER=/target/debug/server
AENV=/target/debug/aenv
PORT=18000
API=http://127.0.0.1:$PORT
ENVD_PORT=49983
IMAGE=${SNAP_IMAGE:-docker.io/library/ubuntu:22.04}
RUNTIME=${SNAP_RUNTIME:-runc}
LOG=/state/snapshot-server.log
RUNTIME_ROOT=/run/yzd-aenv-ct/container/runtime
CAPTURES=$AENV_HOME_PATH/container/fork-captures
VOLUME=snap-vol-$$
FAILURES=0
SERVER_PID=

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }
check() { local label=$1; shift; if "$@"; then pass "$label"; else fail "$label"; fi; }

start_server() {
    sed 's/^enabled_backends = .*/enabled_backends = ["container"]/' "$BASE" > /tmp/snapshot.toml
    printf '\n[container]\nruntime = "%s"\n' "$RUNTIME" >> /tmp/snapshot.toml
    if [ -n "${SNAP_TOOLS_VERSION:-}" ]; then
        sed -i "/^\[tools\]/a version = \"$SNAP_TOOLS_VERSION\"\nurl = \"$SNAP_TOOLS_URL\"" /tmp/snapshot.toml
    fi
    mkdir -p /run/yzd-aenv-ct
    AENV_CONFIG_PATH=/tmp/snapshot.toml API_ADDR=127.0.0.1:$PORT "$SERVER" >> "$LOG" 2>&1 &
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
stop_server() {
    [ -n "$SERVER_PID" ] && kill -TERM "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
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
launch() { # extra-json -> ID, TOKEN, LAUNCH_MS
    local start=$(date +%s%N)
    call POST /sandboxes "{\"templateID\":\"$SNAPSHOT\",\"timeout\":600$1}"
    LAUNCH_MS=$((($(date +%s%N) - start) / 1000000))
    ID=$(jq -r '.sandboxID // empty' <<<"$BODY_OUT")
    TOKEN=$(jq -r '.envdAccessToken // empty' <<<"$BODY_OUT")
}
state_of() { call GET "/sandboxes/$1"; jq -r '.state // empty' <<<"$BODY_OUT"; }
in_box() { "$AENV" exec "$1" -- sh -c "$2" 2>&1; }
start_counter() {
    in_box "$1" 'nohup sh -c "echo \$\$ > /root/counter.pid; i=0; while true; do i=\$((i+1)); echo \$i > /root/count.new; mv /root/count.new /root/count; sleep 0.2; done" >/dev/null 2>&1 &' >/dev/null
}
count_of() { in_box "$1" 'cat /root/count' | grep -E '^[0-9]+$'; }
counter_pid() { in_box "$1" 'p=$(cat /root/counter.pid) && grep -q "while true" /proc/$p/cmdline && echo $p' | grep -E '^[0-9]+$'; }
# Whether envd itself takes a token, asked from inside the sandbox.
envd_accepts() { # id token -> yes/no
    in_box "$1" "/agentenv/bin/busybox wget -q -O /dev/null --header 'X-Access-Token: $2' http://127.0.0.1:$ENVD_PORT/envs && echo yes || echo no" | tail -1
}
captures() { find "$CAPTURES" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l; }
sandbox_mounts() { grep -c "/container/sandboxes/" /proc/self/mountinfo; }
runtime_containers() { "$RUNTIME" --root "$RUNTIME_ROOT" list -q 2>/dev/null | grep -c '^aenv-'; }
volume_ids() { call GET /volumes; jq -r '(arrays // .volumes // [])[] | .volumeID' <<<"$BODY_OUT" | sort; }

: > "$LOG"
start_server
VOLUMES_BEFORE=$(volume_ids)

# --- 1. capture ---------------------------------------------------------------
call POST /volumes "{\"name\":\"$VOLUME\",\"sizeMB\":256}"
check "create volume" test "$STATUS" = 201
call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\",\"timeout\":600,\"secure\":true,\"volumeMounts\":[{\"name\":\"$VOLUME\",\"path\":\"/data\"}]}"
S=$(jq -r '.sandboxID // empty' <<<"$BODY_OUT")
S_TOKEN=$(jq -r '.envdAccessToken // empty' <<<"$BODY_OUT")
check "create a secure source with a volume" test "$STATUS" = 201 -a -n "$S_TOKEN"
in_box "$S" 'echo before > /root/marker && echo before > /data/v && sync' >/dev/null
start_counter "$S"
sleep 1
S_PID=$(counter_pid "$S")
S_COUNT=$(count_of "$S")
START=$(date +%s%N)
call POST "/sandboxes/$S/snapshots" "{\"name\":\"ctsnap-$$\"}"
SNAP_MS=$((($(date +%s%N) - START) / 1000000))
SNAPSHOT=$(jq -r '.snapshotID // empty' <<<"$BODY_OUT")
check "snapshot the source (HTTP $STATUS, ${SNAP_MS} ms)" test "$STATUS" = 201 -a -n "$SNAPSHOT"
[ "$STATUS" = 201 ] || echo "      $BODY_OUT"
check "no capture left behind" test "$(captures)" = 0
check "the source is running" test "$(state_of "$S")" = running
C1=$(count_of "$S"); sleep 0.5; C2=$(count_of "$S")
check "its process runs on ($C1 -> $C2)" test "${C2:-0}" -gt "${C1:-0}"
in_box "$S" 'echo after > /root/marker && echo after > /data/v && sync' >/dev/null

# --- 2. a secure launch ----------------------------------------------------------
launch ',"secure":true'
A=$ID; A_TOKEN=$TOKEN
check "launch from the snapshot (HTTP $STATUS, ${LAUNCH_MS} ms)" test "$STATUS" = 201 -a -n "$A"
[ "$STATUS" = 201 ] || echo "      $BODY_OUT"
check "it is a container" test "$(jq -r .backend <<<"$BODY_OUT")" = container
check "it runs the source's process (pid $S_PID)" test -n "$S_PID" -a "$(counter_pid "$A")" = "$S_PID"
C1=$(count_of "$A"); sleep 0.5; C2=$(count_of "$A")
check "it counts on from the snapshot ($S_COUNT, then $C1 -> $C2)" \
    test "${C1:-0}" -ge "${S_COUNT:-1}" -a "${C2:-0}" -gt "${C1:-0}"
check "its rootfs is as captured" test "$(in_box "$A" 'cat /root/marker')" = before
check "its volume is as captured" test "$(in_box "$A" 'cat /data/v')" = before
check "its envd takes its own token" test "$(envd_accepts "$A" "$A_TOKEN")" = yes
check "and refuses the source's" test "$(envd_accepts "$A" "$S_TOKEN")" = no
check "the source's envd refuses the launch's token" test "$(envd_accepts "$S" "$A_TOKEN")" = no
check "the unpacked dump is gone" test ! -e "$AENV_HOME_PATH/container/sandboxes/$A/criu-images"
in_box "$A" 'echo launched > /data/v && sync' >/dev/null
check "its volume writes stay out of the source" test "$(in_box "$S" 'cat /data/v')" = after

# --- 3. a non-secure launch -----------------------------------------------------
launch ',"secure":false'
B=$ID
check "launch without a token (HTTP $STATUS)" test "$STATUS" = 201 -a -n "$B" -a -z "$TOKEN"
check "it runs the source's process" test "$(counter_pid "$B")" = "$S_PID"
check "its envd takes no token" test "$(envd_accepts "$B" "")" = yes
check "and its volume is its own copy as captured" test "$(in_box "$B" 'cat /data/v')" = before

# --- 4. the snapshot outlives its source ------------------------------------------
call DELETE "/sandboxes/$S"
check "delete the source (HTTP $STATUS)" test "$STATUS" = 204
launch ',"secure":true'
C=$ID
check "launch after the source is gone (HTTP $STATUS)" test "$STATUS" = 201 -a -n "$C"
check "it runs the source's process" test "$(counter_pid "$C")" = "$S_PID"

# --- 5. a launch cannot change the mounts ---------------------------------------------
launch ",\"volumeMounts\":[{\"name\":\"$VOLUME\",\"path\":\"/other\"}]"
check "a launch with other volumes is refused (HTTP $STATUS)" test "$STATUS" = 400

# --- cleanup ---------------------------------------------------------------------
for id in "$A" "$B" "$C"; do call DELETE "/sandboxes/$id"; done
call DELETE "/snapshots/$SNAPSHOT"
check "delete the snapshot (HTTP $STATUS)" test "$STATUS" = 204 -o "$STATUS" = 200
for volume in $(comm -13 <(echo "$VOLUMES_BEFORE") <(volume_ids)); do
    call DELETE "/volumes/$volume"
done
check "no runtime containers left" test "$(runtime_containers)" = 0
check "no sandbox mounts left" test "$(sandbox_mounts)" = 0
check "no capture left" test "$(captures)" = 0
stop_server

echo
if [ "$FAILURES" -eq 0 ]; then echo "container snapshot: all checks passed"; else echo "container snapshot: $FAILURES check(s) failed"; exit 1; fi
