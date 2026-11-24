#!/bin/bash
# Regression tests for the cross-phase review of the container backend.
# Needs a debug build: the failure cases use AENV_FAILPOINTS, which release
# builds ignore. Run as root inside the dev container after building the
# server, ublk daemon and CLI (see the C2 smoke test):
#   docker exec yzd-aenv-ct-dev bash /src/scripts/tests/container-backend-review/regressions.sh
#
# 1. A drive that fails to mount mid-way through a multi-drive start leaves
#    no ublk device or mount behind.
# 2. A subPath is never resolved through a symbolic link in the drive.
# 3. The OCI bundle's seccomp filter refuses namespace and mount syscalls.
# 4. A restack that fails after the device moved to the new upper leaves the
#    sandbox out of Running.
# 5. An image whose upload is slow still publishes and starts when the
#    source sandbox is deleted during the upload.
set -uo pipefail

BASE=/src/scripts/tests/container-backend-c0/c0.toml
SERVER=/target/debug/server
AENV=/target/debug/aenv
PORT=18000
API=http://127.0.0.1:$PORT
IMAGE=${REVIEW_IMAGE:-docker.io/library/ubuntu:22.04}
DRIVE_IMAGE=${REVIEW_DRIVE_IMAGE:-docker.io/library/alpine:3.19}
LOG=/state/review-server.log
FAILURES=0
SERVER_PID=

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }
check() { local label=$1; shift; if "$@"; then pass "$label"; else fail "$label"; fi; }

# start_server FAILPOINTS
start_server() {
    sed 's/^enabled_backends = .*/enabled_backends = ["firecracker", "container"]/' "$BASE" > /tmp/review.toml
    mkdir -p /run/yzd-aenv-ct
    echo "=== server with AENV_FAILPOINTS='$1'" >> "$LOG"
    AENV_FAILPOINTS=$1 AENV_CONFIG_PATH=/tmp/review.toml API_ADDR=127.0.0.1:$PORT \
        "$SERVER" >> "$LOG" 2>&1 &
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
create() { # image extra-json -> ID
    call POST /sandboxes-cold "{\"image\":\"$1\",\"backend\":\"container\",\"timeout\":300$2}"
    ID=$(jq -r .sandboxID <<<"$BODY_OUT")
    [ "$STATUS" = 201 ]
}
in_box() { "$AENV" exec "$1" -- sh -c "$2" 2>&1; }
# Devices owned by this server's ublk daemon; other instances' devices are
# counted too but do not change while the test runs.
ublk_devices() { find /dev -maxdepth 1 -name 'ublkb*' 2>/dev/null | wc -l; }
sandbox_mounts() { grep -c "/container/sandboxes/" /proc/self/mountinfo; }
drive() { # id mountPath [subPath] [image]
    printf '{"driveID":"%s","source":{"image":"%s"},"mountPath":"%s","readOnly":true%s}' \
        "$1" "${4:-$DRIVE_IMAGE}" "$2" "${3:+,\"subPath\":\"$3\"}"
}

: > "$LOG"

# --- 1. multi-drive mid-failure ------------------------------------------------
start_server "container-mount-drive:d2"
# Warm the drive image so the baseline excludes nothing transient.
create "$IMAGE" ",\"attachedDrives\":[$(drive d1 /mnt/d1)]"
check "single drive starts (d2 is the armed one)" test "$STATUS" = 201
call DELETE "/sandboxes/$ID"
sleep 2
BASE_DEVICES=$(ublk_devices)
BASE_MOUNTS=$(sandbox_mounts)
create "$IMAGE" ",\"attachedDrives\":[$(drive d1 /mnt/d1),$(drive d2 /mnt/d2),$(drive d3 /mnt/d3)]"
check "start fails when the second drive cannot mount (HTTP $STATUS)" test "$STATUS" != 201
grep -q "failpoint container-mount-drive triggered" "$LOG"
check "the failure came from the failpoint" test $? = 0
sleep 2
check "ublk devices back to baseline ($(ublk_devices) vs $BASE_DEVICES)" test "$(ublk_devices)" = "$BASE_DEVICES"
check "no sandbox mounts left" test "$(sandbox_mounts)" = "$BASE_MOUNTS"
stop_server

# --- 2 and 3. subPath links and seccomp -----------------------------------------
start_server ""
NAME=review-link-$$
create "$IMAGE" ""
A=$ID
in_box "$A" 'ln -s /etc /escape && mkdir -p /data/inner && ln -s inner /data/rel && echo ok > /data/inner/f' >/dev/null
call POST "/sandboxes/$A/images" "{\"name\":\"$NAME\"}"
check "publish an image with planted links" test "$STATUS" = 201
LINKED=$(jq -r .image <<<"$BODY_OUT")

for sub in escape escape/passwd data/rel; do
    create "$IMAGE" ",\"attachedDrives\":[$(drive l /mnt/l "$sub" "$LINKED")]"
    check "subPath '$sub' through a link is refused (HTTP $STATUS)" test "$STATUS" != 201
done
grep -q "crosses a symbolic link" "$LOG"
check "refusals name the symbolic link" test $? = 0
create "$IMAGE" ",\"attachedDrives\":[$(drive l /mnt/l data/inner "$LINKED")]"
check "a plain subPath still works" test "$STATUS" = 201
L=$ID
check "it exposes only that directory" test "$(in_box "$L" 'cat /mnt/l/f')" = ok

OUT=$(in_box "$A" 'grep ^Seccomp: /proc/self/status')
check "processes run under a seccomp filter ($OUT)" grep -q 'Seccomp:[[:space:]]*2' <<<"$OUT"
OUT=$(in_box "$A" 'unshare -U true && echo allowed || echo refused')
check "unshare is refused" grep -qx refused <<<"$(tail -1 <<<"$OUT")"
OUT=$(in_box "$A" 'mount -t tmpfs none /mnt && echo allowed || echo refused')
check "mount is refused" grep -qx refused <<<"$(tail -1 <<<"$OUT")"
check "ordinary processes still start" test "$(in_box "$A" 'sh -c "echo child"')" = child
for id in "$A" "$L"; do call DELETE "/sandboxes/$id"; done
stop_server

# --- 4. terminal restack failure ------------------------------------------------
start_server "restack-rewrite-config"
create "$IMAGE" ""
R=$ID
call POST "/sandboxes/$R/images" '{"name":"review-restack"}'
check "publish fails when the restack fails late (HTTP $STATUS)" test "$STATUS" = 500
call GET "/sandboxes/$R"
STATE=$(jq -r '.state // empty' <<<"$BODY_OUT")
check "the sandbox is not Running afterwards (HTTP $STATUS, state '${STATE}')" \
    test "$STATUS" != 200 -o "$STATE" != running
call DELETE "/sandboxes/$R"
stop_server

# --- 5. delete during a slow upload ----------------------------------------------
start_server "publish-rootfs-delay=8000"
create "$IMAGE" ""
S=$ID
in_box "$S" 'echo kept > /root/marker' >/dev/null
NAME=review-race-$$
(call POST "/sandboxes/$S/images" "{\"name\":\"$NAME\"}"; echo "$STATUS" > /tmp/review-publish.status) &
PUBLISH=$!
sleep 3
call DELETE "/sandboxes/$S"
check "the source deletes while its image uploads" test "$STATUS" = 204
wait "$PUBLISH"
check "the upload still publishes" test "$(cat /tmp/review-publish.status)" = 201
create "aenv/$NAME:latest" ""
check "and the image starts" test "$STATUS" = 201
P=$ID
check "with the source's files" test "$(in_box "$P" 'cat /root/marker')" = kept
call DELETE "/sandboxes/$P"
sleep 1
check "no sandbox mounts left" test "$(sandbox_mounts)" = 0
stop_server

echo
if [ "$FAILURES" -eq 0 ]; then echo "review regressions: all checks passed"; else echo "review regressions: $FAILURES check(s) failed"; exit 1; fi
