#!/bin/bash
# Does a full fork child get its memory and its volume from the same instant?
#
# The source runs genlog (genlog.c), which appends 1, 2, 3, ... to a log on
# its volume and fsyncs each line, keeping the counter only in memory. A
# child carries on appending from the counter it was restored with. If its
# volume was sealed earlier than its memory was captured, the numbers in
# between never reach its log: the log has a gap, or, once its cached pages
# are dropped, garbage. So each child's writer is stopped and its log checked
# for exactly 1..N. The log keeps its history, so this holds however long the
# child ran before the check.
#
#   1. Container full fork: every child's log must be gapless.
#   2. Positive control: a Firecracker full fork on this same build, which
#      seals the volume before it captures memory. It must show a gap in at
#      least one child, or this test cannot see the problem it checks for.
#      CONSISTENCY_CONTROL=0 skips it (e.g. on a node without KVM); once
#      Firecracker forks capture first too, expect it to find no gap.
#
# Run as root inside the dev container after building the server, ublk
# daemon and CLI; needs gcc for the static genlog binary:
#   docker exec yzd-aenv-ct-dev bash /src/scripts/tests/container-backend-fullfork/consistency.sh
# CONSISTENCY_ROUNDS (default 5) forks of CONSISTENCY_COUNT (default 3)
# children per backend; CONSISTENCY_INTERVAL_US (default 1000) between
# records, each a 4 KiB page.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BASE=/src/scripts/tests/container-backend-c0/c0.toml
SERVER=/target/debug/server
AENV=/target/debug/aenv
PORT=18000
API=http://127.0.0.1:$PORT
IMAGE=${CONSISTENCY_IMAGE:-docker.io/library/ubuntu:22.04}
ROUNDS=${CONSISTENCY_ROUNDS:-5}
COUNT=${CONSISTENCY_COUNT:-3}
INTERVAL_US=${CONSISTENCY_INTERVAL_US:-1000}
CONTROL=${CONSISTENCY_CONTROL:-1}
LOG=/state/consistency-server.log
WORK=$(mktemp -d /state/consistency.XXXXXX)
GENLOG=$WORK/genlog
FAILURES=0
SERVER_PID=
FC_BEFORE=$(pgrep -x firecracker | sort)

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }
check() { local label=$1; shift; if "$@"; then pass "$label"; else fail "$label"; fi; }

start_server() {
    # No warm Firecracker pool: its VMs would outlive the server.
    sed -e 's/^enabled_backends = .*/enabled_backends = ["container", "firecracker"]/' \
        -e '/^\[pool.firecracker\]/,/^\[/{s/^enabled = true/enabled = false/;s/^startup_prewarm = true/startup_prewarm = false/;}' \
        "$BASE" > "$WORK/server.toml"
    mkdir -p /run/yzd-aenv-ct
    AENV_CONFIG_PATH=$WORK/server.toml API_ADDR=127.0.0.1:$PORT "$SERVER" >> "$LOG" 2>&1 &
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
cleanup() {
    stop_server
    # Firecracker processes started since this script began are its own.
    for pid in $(comm -13 <(echo "$FC_BEFORE") <(pgrep -x firecracker | sort)); do
        echo "      stopping leftover firecracker $pid"
        kill -TERM "$pid" 2>/dev/null
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

call() {
    local out
    out=$(curl -s -w '\n%{http_code}' -X "$1" "$API$2" -H "X-API-Key: $KEY" \
        -H 'Content-Type: application/json' ${3:+-d "$3"})
    STATUS=${out##*$'\n'}
    BODY_OUT=${out%$'\n'*}
}
in_box() { "$AENV" exec "$1" -- sh -c "$2" 2>&1; }
fork_copies() {
    call GET /volumes
    jq -r '(arrays // .volumes // [])[] | select(.name | startswith("volume-fork-")) | .volumeID' \
        <<<"$BODY_OUT" | sort
}
# Stops the box's writer and checks its log; prints genlog's verdict.
stop_and_check() {
    in_box "$1" 'kill -STOP "$(cat /root/genlog.pid)" && sleep 0.2 && /root/genlog check /data/gen.log' | tail -1
}

# Runs ROUNDS forks of COUNT children from one source on BACKEND; sets
# CHILDREN (checked) and GAPS (children whose log broke).
run_backend() { # backend
    local backend=$1 volume=consistency-$1-$$ source child verdict before
    CHILDREN=0; GAPS=0
    call POST /volumes "{\"name\":\"$volume\",\"sizeMB\":2048}"
    check "$backend: create a volume" test "$STATUS" = 201
    call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"$backend\",\"timeout\":900,\"volumeMounts\":[{\"name\":\"$volume\",\"path\":\"/data\"}]}"
    source=$(jq -r '.sandboxID // empty' <<<"$BODY_OUT")
    check "$backend: create the source (HTTP $STATUS)" test "$STATUS" = 201 -a -n "$source"
    "$AENV" upload --user root "$source" "$GENLOG" /root/genlog >/dev/null 2>&1
    in_box "$source" "chmod 755 /root/genlog && nohup /root/genlog write /data/gen.log /root/genlog.pid $INTERVAL_US </dev/null >/dev/null 2>&1 &" >/dev/null
    sleep 1
    check "$backend: the writer runs" test -n "$(in_box "$source" 'tail -1 /data/gen.log' | tr -d ' ' | grep -E '^[0-9]+$')"

    for round in $(seq 1 "$ROUNDS"); do
        before=$(fork_copies)
        call POST "/sandboxes/$source/fork" "{\"count\":$COUNT,\"mode\":\"full\"}"
        mapfile -t KIDS < <(jq -r 'arrays | .[] | .sandbox.sandboxID // empty' <<<"$BODY_OUT")
        if [ "$STATUS" != 201 ] || [ "${#KIDS[@]}" != "$COUNT" ]; then
            fail "$backend round $round: fork (HTTP $STATUS, ${#KIDS[@]} children)"
        fi
        for child in "${KIDS[@]}"; do
            verdict=$(stop_and_check "$child")
            CHILDREN=$((CHILDREN + 1))
            case "$verdict" in
                ok\ *) ;;
                *) GAPS=$((GAPS + 1)) ;;
            esac
            echo "      $backend round $round child ${child:0:13}: $verdict"
            call DELETE "/sandboxes/$child"
        done
        # The children's volume copies are not needed any more.
        for copy in $(comm -13 <(echo "$before") <(fork_copies)); do
            call DELETE "/volumes/$copy"
        done
        sleep 0.5
    done

    verdict=$(stop_and_check "$source")
    check "$backend: the source's own log is gapless ($verdict)" test "${verdict%% *}" = ok
    call DELETE "/sandboxes/$source"
    call DELETE "/volumes/$volume"
}

: > "$LOG"
gcc -O2 -Wall -Wextra -Werror -static -o "$GENLOG" "$HERE/genlog.c" || { echo "cannot build genlog"; exit 1; }

# The checker itself: a log with a hole must not pass.
printf '1  \n2  \n3  \n' > "$WORK/good.log"
printf '1  \n2  \n5  \n6  \n' > "$WORK/gap.log"
printf '1  \n2  \n\0\0\0\n' > "$WORK/zeros.log"
check "checker accepts 1..3" test "$("$GENLOG" check "$WORK/good.log")" = "ok 3"
check "checker rejects a gap" test "$("$GENLOG" check "$WORK/gap.log" | cut -d: -f1)" = gap
check "checker rejects zeroed bytes" test "$("$GENLOG" check "$WORK/zeros.log" | cut -d' ' -f1)" = bad

start_server

run_backend container
check "container: no child of $CHILDREN has a gap ($GAPS found)" test "$CHILDREN" -gt 0 -a "$GAPS" = 0

if [ "$CONTROL" = 1 ]; then
    run_backend firecracker
    check "control: the Firecracker fork shows the gap this test detects ($GAPS of $CHILDREN children)" \
        test "$GAPS" -gt 0
    [ "$GAPS" = "$CHILDREN" ] || echo "      note: the control missed $((CHILDREN - GAPS)) children"

fi

stop_server
echo
if [ "$FAILURES" -eq 0 ]; then echo "consistency: all checks passed"; else echo "consistency: $FAILURES check(s) failed"; exit 1; fi
