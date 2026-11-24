#!/bin/bash
# Persistent pause and resume of container sandboxes: CRIU dump plus sealed
# rootfs and drives, every runtime resource released, and the same processes
# restored into a new container.
#
#   1. A pause that fails after the dump thaws the sandbox and keeps it running.
#   2. A pause releases the container, devices, mounts, work directory and
#      cgroup, and leaves the dump and sealed layers in the artifact root.
#   3. A resume that fails leaves the sandbox paused and nothing behind.
#   4. The paused sandbox survives a server restart and resumes with the same
#      processes, files and volume; it pauses and resumes (connect) again.
#   5. Deleting it removes its artifacts and releases its volume.
#   6. A timed-out sandbox pauses, a running one pauses at shutdown, and the
#      latter resumes after the restart.
#   7. A pause whose record cannot be written leaves the sandbox running on
#      intact layers: it pauses and resumes later with all its files.
#   8. A resumed sandbox with a read-only drive forks, and its child forks
#      again after the parent is deleted.
#   9. A node whose runtime cannot checkpoint refuses autoPause and deletes
#      container sandboxes on timeout.
#
# Each resume releases the dump it came from. PAUSE_RUNTIME=crun runs it all
# under crun (default runc).
#
# Needs a debug build (cases 1, 3 and 7 use AENV_FAILPOINTS) and criu. Run as root
# inside the dev container after building the server, ublk daemon and CLI:
#   docker exec yzd-aenv-ct-dev bash /src/scripts/tests/container-backend-pause/pause.sh
set -uo pipefail

BASE=/src/scripts/tests/container-backend-c0/c0.toml
SERVER=/target/debug/server
AENV=/target/debug/aenv
PORT=18000
API=http://127.0.0.1:$PORT
IMAGE=${PAUSE_IMAGE:-docker.io/library/ubuntu:22.04}
DRIVE_IMAGE=${PAUSE_DRIVE_IMAGE:-docker.io/library/alpine:3.19}
RUNTIME=${PAUSE_RUNTIME:-runc}
LOG=/state/pause-server.log
RUNTIME_ROOT=/run/yzd-aenv-ct/container/runtime
ARTIFACTS=$AENV_HOME_PATH/persisted-sandboxes/artifacts
VOLUME=pause-vol-$$
FAILURES=0
SERVER_PID=

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }
check() { local label=$1; shift; if "$@"; then pass "$label"; else fail "$label"; fi; }

start_server() { # FAILPOINTS [RUNTIME]
    sed 's/^enabled_backends = .*/enabled_backends = ["container"]/' "$BASE" > /tmp/pause.toml
    printf '\n[container]\nruntime = "%s"\n' "${2:-$RUNTIME}" >> /tmp/pause.toml
    mkdir -p /run/yzd-aenv-ct
    echo "=== server with AENV_FAILPOINTS='$1'" >> "$LOG"
    AENV_FAILPOINTS=$1 AENV_CONFIG_PATH=/tmp/pause.toml API_ADDR=127.0.0.1:$PORT \
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
create() { # extra-json -> ID
    call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\",\"timeout\":600$1}"
    ID=$(jq -r .sandboxID <<<"$BODY_OUT")
    [ "$STATUS" = 201 ]
}
state_of() { call GET "/sandboxes/$1"; jq -r '.state // empty' <<<"$BODY_OUT"; }
in_box() { "$AENV" exec "$1" -- sh -c "$2" 2>&1; }
start_counter() {
    in_box "$1" 'nohup sh -c "echo \$\$ > /root/counter.pid; i=0; while true; do i=\$((i+1)); echo \$i > /root/count; sleep 0.2; done" >/dev/null 2>&1 &' >/dev/null
}
count_of() { in_box "$1" 'cat /root/count'; }
# The counter's pid, if that process is still the counter.
counter_pid() { in_box "$1" 'p=$(cat /root/counter.pid) && grep -q "while true" /proc/$p/cmdline && echo $p'; }
resume() { # id -> RESUME_MS
    local start=$(date +%s%N)
    call POST "/sandboxes/$1/resume" '{"timeout":600}'
    RESUME_MS=$((($(date +%s%N) - start) / 1000000))
}
ublk_devices() { find /dev -maxdepth 1 -name 'ublkb*' 2>/dev/null | wc -l; }
sandbox_mounts() { grep -c "/container/sandboxes/" /proc/self/mountinfo; }
runtime_containers() { "$RUNTIME" --root "$RUNTIME_ROOT" list -q 2>/dev/null | grep -c '^aenv-'; }
dump_of() { find "$ARTIFACTS/$1" -name inventory.img 2>/dev/null | head -1; }
dumps_of() { find "$ARTIFACTS/$1" -name inventory.img 2>/dev/null | wc -l; }
pause() { # id -> PAUSE_MS
    local start=$(date +%s%N)
    call POST "/sandboxes/$1/pause"
    PAUSE_MS=$((($(date +%s%N) - start) / 1000000))
}

: > "$LOG"

# --- 1. a failed pause thaws the sandbox -------------------------------------
start_server "container-pause-seal"
create ""
A=$ID
start_counter "$A"
sleep 1
pause "$A"
check "a pause that fails after the dump is refused (HTTP $STATUS)" test "$STATUS" != 204
grep -q "failpoint container-pause-seal triggered" "$LOG"
check "the failure came from the failpoint" test $? = 0
check "the sandbox is running again" test "$(state_of "$A")" = running
BEFORE=$(count_of "$A"); sleep 1; AFTER=$(count_of "$A")
check "its processes run again ($BEFORE -> $AFTER)" test "${AFTER:-0}" -gt "${BEFORE:-0}"
call DELETE "/sandboxes/$A"
stop_server

# --- 2. pause releases everything --------------------------------------------
start_server "container-restore"
create ""                       # warm the image and the shared tools drive
call DELETE "/sandboxes/$ID"
sleep 1
BASE_DEVICES=$(ublk_devices)
call POST /volumes "{\"name\":\"$VOLUME\",\"sizeMB\":256}"
check "create volume" test "$STATUS" = 201
create ",\"volumeMounts\":[{\"name\":\"$VOLUME\",\"path\":\"/data\"}]"
check "create a sandbox with a volume" test "$STATUS" = 201
B=$ID
in_box "$B" 'echo kept > /root/marker && echo on-volume > /data/v && sync' >/dev/null
start_counter "$B"
sleep 1
PID_BEFORE=$(counter_pid "$B")
COUNT_BEFORE=$(count_of "$B")
pause "$B"
check "pause (HTTP $STATUS, ${PAUSE_MS} ms)" test "$STATUS" = 204
check "state is paused" test "$(state_of "$B")" = paused
check "no runtime container left" test "$(runtime_containers)" = 0
check "no sandbox mounts left" test "$(sandbox_mounts)" = 0
check "ublk devices back to baseline ($(ublk_devices) vs $BASE_DEVICES)" test "$(ublk_devices)" -le "$BASE_DEVICES"
check "work directory removed" test ! -e "$AENV_HOME_PATH/container/sandboxes/$B"
check "cgroup removed" test ! -e "/sys/fs/cgroup/aenv-container/aenv-$B"
DUMP=$(dump_of "$B")
check "the CRIU dump is in the artifact root" test -n "$DUMP"
check "the sealed rootfs is next to it" test -f "$(dirname "$(dirname "$DUMP")")/rootfs/image.json"
echo "      artifacts: $(du -sh "$ARTIFACTS/$B" | cut -f1)"
pause "$B"
check "pausing again is a no-op (HTTP $STATUS)" test "$STATUS" = 204

# --- 3. a failed resume leaves it paused ---------------------------------------
resume "$B"
check "a resume that fails is refused (HTTP $STATUS)" test "$STATUS" != 201
grep -q "failpoint container-restore triggered" "$LOG"
check "the failure came from the failpoint" test $? = 0
check "the sandbox is still paused" test "$(state_of "$B")" = paused
check "its dump is still there" test -n "$(dump_of "$B")"
check "no runtime container left" test "$(runtime_containers)" = 0
check "no sandbox mounts left" test "$(sandbox_mounts)" = 0

# --- 4. restart, resume, pause and resume again -----------------------------------
stop_server
start_server ""
check "still paused after a restart" test "$(state_of "$B")" = paused
grep -q "discarding unusable paused sandbox record" "$LOG"
check "its record was not discarded" test $? != 0
resume "$B"
check "resume (HTTP $STATUS, ${RESUME_MS} ms)" test "$STATUS" = 201
check "state is running" test "$(state_of "$B")" = running
check "the resume released its dump" test "$(dumps_of "$B")" = 0
PID_AFTER=$(counter_pid "$B")
check "the same process runs on (pid $PID_BEFORE -> $PID_AFTER)" test -n "$PID_AFTER" -a "$PID_AFTER" = "$PID_BEFORE"
C1=$(count_of "$B"); sleep 1; C2=$(count_of "$B")
check "it keeps counting from where it was ($COUNT_BEFORE, then $C1 -> $C2)" \
    test "${C1:-0}" -ge "${COUNT_BEFORE:-1}" -a "${C2:-0}" -gt "${C1:-0}"
check "rootfs files are back" test "$(in_box "$B" 'cat /root/marker')" = kept
check "volume files are back" test "$(in_box "$B" 'cat /data/v')" = on-volume
check "the volume is writable" test "$(in_box "$B" 'echo again > /data/w && cat /data/w')" = again
check "one runtime container" test "$(runtime_containers)" = 1
pause "$B"
check "pause again (HTTP $STATUS, ${PAUSE_MS} ms)" test "$STATUS" = 204
check "one dump while paused" test "$(dumps_of "$B")" = 1
call POST "/sandboxes/$B/connect" '{"timeout":600}'
check "connect resumes it (HTTP $STATUS)" test "$STATUS" = 201
check "and releases that dump too" test "$(dumps_of "$B")" = 0
check "the same process still runs" test "$(counter_pid "$B")" = "$PID_BEFORE"
check "the second volume write is kept" test "$(in_box "$B" 'cat /data/w')" = again

# --- 5. delete --------------------------------------------------------------------
pause "$B"
check "pause a third time (HTTP $STATUS)" test "$STATUS" = 204
call DELETE "/sandboxes/$B"
check "delete the paused sandbox (HTTP $STATUS)" test "$STATUS" = 204
check "its artifacts are gone" test ! -e "$ARTIFACTS/$B"
call DELETE "/volumes/$VOLUME"
check "its volume is released (HTTP $STATUS)" test "$STATUS" = 204

# --- 6. timeout and shutdown pause ---------------------------------------------
call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\",\"timeout\":3}"
C=$(jq -r .sandboxID <<<"$BODY_OUT")
check "create a sandbox with a short timeout" test "$STATUS" = 201
for _ in $(seq 1 60); do [ "$(state_of "$C")" = paused ] && break; sleep 1; done
check "it pauses when it times out" test "$(state_of "$C")" = paused
create ""
D=$ID
start_counter "$D"
sleep 1
PID_D=$(counter_pid "$D")
stop_server
start_server ""
check "a running sandbox pauses at shutdown" test "$(state_of "$D")" = paused
resume "$D"
check "and resumes after the restart (HTTP $STATUS, ${RESUME_MS} ms)" test "$STATUS" = 201
check "with the same process" test "$(counter_pid "$D")" = "$PID_D"
for id in "$C" "$D"; do call DELETE "/sandboxes/$id"; done

# --- 7. the pause record cannot be written ------------------------------------------
stop_server
start_server "persist-paused-record*1"
create ""
E=$ID
in_box "$E" 'echo first > /root/first && sync' >/dev/null
pause "$E"
check "a pause whose record fails is refused (HTTP $STATUS)" test "$STATUS" != 204
grep -q "failpoint persist-paused-record triggered" "$LOG"
check "the failure came from the failpoint" test $? = 0
check "the sandbox is running again" test "$(state_of "$E")" = running
check "its failed pause left no artifacts" test -z "$(ls -A "$ARTIFACTS/$E" 2>/dev/null)"
in_box "$E" 'echo second > /root/second && sync' >/dev/null
pause "$E"
check "it pauses next time (HTTP $STATUS)" test "$STATUS" = 204
resume "$E"
check "and resumes (HTTP $STATUS)" test "$STATUS" = 201
check "with the files from before and after the failed pause" \
    test "$(in_box "$E" 'cat /root/first /root/second' | tr '\n' ' ')" = "first second "
pause "$E"
check "and pauses again (HTTP $STATUS)" test "$STATUS" = 204
call DELETE "/sandboxes/$E"

# --- 8. fork chain through a resumed sandbox with a read-only drive -------------------
DRIVE="{\"driveID\":\"ro\",\"source\":{\"image\":\"$DRIVE_IMAGE\"},\"mountPath\":\"/mnt/ro\",\"readOnly\":true}"
create ",\"attachedDrives\":[$DRIVE]"
check "create a sandbox with a read-only drive" test "$STATUS" = 201
F=$ID
pause "$F"; check "pause it (HTTP $STATUS)" test "$STATUS" = 204
resume "$F"; check "resume it (HTTP $STATUS)" test "$STATUS" = 201
call POST "/sandboxes/$F/fork" '{"count":1,"mode":"filesystem"}'
G=$(jq -r '.[0].sandbox.sandboxID // empty' <<<"$BODY_OUT")
check "fork it (HTTP $STATUS)" test "$STATUS" = 201 -a -n "$G"
call DELETE "/sandboxes/$F"
check "delete the parent (HTTP $STATUS)" test "$STATUS" = 204
call POST "/sandboxes/$G/fork" '{"count":1,"mode":"filesystem"}'
H=$(jq -r '.[0].sandbox.sandboxID // empty' <<<"$BODY_OUT")
check "the child forks again (HTTP $STATUS)" test "$STATUS" = 201 -a -n "$H"
check "the grandchild sees the drive" test -n "$(in_box "$H" 'cat /mnt/ro/etc/alpine-release')"
for id in "$G" "$H"; do call DELETE "/sandboxes/$id"; done

call GET /sandboxes
check "no sandbox left" test "$(jq 'length' <<<"$BODY_OUT")" = 0
stop_server

# --- 9. a runtime that cannot checkpoint ------------------------------------------------
# Only the capability decision is under test: a stub named runsc that fails
# every command stands in for gVisor, which this host does not have.
STUB_DIR=$(mktemp -d /tmp/pause-runsc.XXXXXX)
printf '#!/bin/sh\nexit 1\n' > "$STUB_DIR/runsc"
chmod +x "$STUB_DIR/runsc"
start_server "" "$STUB_DIR/runsc"
call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\",\"autoPause\":true}"
check "runsc refuses autoPause (HTTP $STATUS $(jq -r .reason <<<"$BODY_OUT"))" \
    test "$STATUS/$(jq -r .reason <<<"$BODY_OUT")" = "400/unsupported_capability"
grep -q "container sandboxes cannot pause on this node" "$LOG"
check "the node says why" test $? = 0
stop_server
rm -rf -- "$STUB_DIR"
check "no sandbox mounts left" test "$(sandbox_mounts)" = 0
check "no runtime container left" test "$(runtime_containers)" = 0
check "no artifacts left" test -z "$(ls -A "$ARTIFACTS" 2>/dev/null)"

echo
if [ "$FAILURES" -eq 0 ]; then echo "container pause: all checks passed"; else echo "container pause: $FAILURES check(s) failed; log in $LOG"; exit 1; fi
