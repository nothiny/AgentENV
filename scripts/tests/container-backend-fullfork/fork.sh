#!/bin/bash
# Full fork of container sandboxes: the source is dumped once with CRIU,
# its volumes and rootfs sealed in the same frozen window, and each child
# restores that dump with its own ID, token, rootfs upper, volume copy,
# network slot and cgroup.
#
#   1. A fork whose capture fails after the dump leaves the source running and
#      no capture behind.
#   2. A secure source with a volume forks into three children:
#      - each runs the source's processes (same PID, counting on);
#      - the rootfs and volume match what the source wrote before the fork;
#      - each child's envd takes only its own token (the source's and a
#        sibling's are refused), checked from inside the sandbox since the
#        proxy checks tokens on its own; this needs the patched envd;
#      - writes stay in the sandbox that made them;
#      - the dump is gone once the fork returns.
#   3. A fork where one child fails to restore: the others run, and the failed
#      child's volume copy is deleted.
#   4. Children outlive their deleted source (same process, still counting),
#      and delete cleanly.
#
# Needs a debug build (AENV_FAILPOINTS), criu, and a tools image with the
# access-token-file envd patch (images/tools/patches). Run as root inside the
# dev container after building the server, ublk daemon and CLI:
#   docker exec yzd-aenv-ct-dev bash /src/scripts/tests/container-backend-fullfork/fork.sh
# FORK_RUNTIME=crun runs it under crun (default runc). FORK_TOOLS_VERSION and
# FORK_TOOLS_URL select a tools image that is not yet released, for example
#   FORK_TOOLS_VERSION=0.1.2-dev.1 FORK_TOOLS_URL='ocidir:///state/tools-oci:{version}'
# after building it with images/tools and importing it with
# `regctl image import ocidir:///state/tools-oci:0.1.2-dev.1 tools.tar`.
set -uo pipefail

BASE=/src/scripts/tests/container-backend-c0/c0.toml
SERVER=/target/debug/server
AENV=/target/debug/aenv
PORT=18000
API=http://127.0.0.1:$PORT
ENVD_PORT=49983
IMAGE=${FORK_IMAGE:-docker.io/library/ubuntu:22.04}
RUNTIME=${FORK_RUNTIME:-runc}
LOG=/state/fullfork-server.log
RUNTIME_ROOT=/run/yzd-aenv-ct/container/runtime
CAPTURES=$AENV_HOME_PATH/container/fork-captures
VOLUME=fork-vol-$$
FAILURES=0
SERVER_PID=

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }
check() { local label=$1; shift; if "$@"; then pass "$label"; else fail "$label"; fi; }

start_server() { # FAILPOINTS
    sed 's/^enabled_backends = .*/enabled_backends = ["container"]/' "$BASE" > /tmp/fullfork.toml
    printf '\n[container]\nruntime = "%s"\n' "$RUNTIME" >> /tmp/fullfork.toml
    if [ -n "${FORK_TOOLS_VERSION:-}" ]; then
        # A tools image other than the release, e.g. one built with the envd
        # patch: FORK_TOOLS_URL is a reference template with {version}.
        sed -i "/^\[tools\]/a version = \"$FORK_TOOLS_VERSION\"\nurl = \"$FORK_TOOLS_URL\"" /tmp/fullfork.toml
    fi
    mkdir -p /run/yzd-aenv-ct
    echo "=== server with AENV_FAILPOINTS='$1'" >> "$LOG"
    AENV_FAILPOINTS=$1 AENV_CONFIG_PATH=/tmp/fullfork.toml API_ADDR=127.0.0.1:$PORT \
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
create() { # extra-json -> ID, TOKEN
    call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\",\"timeout\":600,\"secure\":true$1}"
    ID=$(jq -r .sandboxID <<<"$BODY_OUT")
    TOKEN=$(jq -r '.envdAccessToken // empty' <<<"$BODY_OUT")
    [ "$STATUS" = 201 ]
}
fork() { # id count -> FORK_MS, KIDS, KID_TOKENS
    local start=$(date +%s%N)
    call POST "/sandboxes/$1/fork" "{\"count\":$2,\"mode\":\"full\"}"
    FORK_MS=$((($(date +%s%N) - start) / 1000000))
    mapfile -t KIDS < <(jq -r 'arrays | .[] | .sandbox.sandboxID // empty' <<<"$BODY_OUT")
    mapfile -t KID_TOKENS < <(jq -r 'arrays | .[] | .sandbox.envdAccessToken // empty' <<<"$BODY_OUT")
}
state_of() { call GET "/sandboxes/$1"; jq -r '.state // empty' <<<"$BODY_OUT"; }
in_box() { "$AENV" exec "$1" -- sh -c "$2" 2>&1; }
# Writes go through a rename, so a read never sees the file truncated.
start_counter() {
    in_box "$1" 'nohup sh -c "echo \$\$ > /root/counter.pid; i=0; while true; do i=\$((i+1)); echo \$i > /root/count.new; mv /root/count.new /root/count; sleep 0.2; done" >/dev/null 2>&1 &' >/dev/null
}
# Numbers only, so error text from a failed exec never passes for one.
count_of() { in_box "$1" 'cat /root/count' | grep -E '^[0-9]+$'; }
counter_pid() { in_box "$1" 'p=$(cat /root/counter.pid) && grep -q "while true" /proc/$p/cmdline && echo $p' | grep -E '^[0-9]+$'; }
# Whether envd itself accepts a token: asked from inside the sandbox, so the
# sandbox proxy, which checks tokens on its own, is not in the way.
envd_accepts() { # id token -> yes/no
    in_box "$1" "/agentenv/bin/busybox wget -q -O /dev/null --header 'X-Access-Token: $2' http://127.0.0.1:$ENVD_PORT/envs && echo yes || echo no" | tail -1
}
# HTTP status of an envd file read through the sandbox proxy with a token.
envd_read() { # id token
    curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        -H "x-agentenv-sandbox-id: $1" -H "x-agentenv-target-port: $ENVD_PORT" \
        -H "X-Access-Token: $2" "$API/proxy/files?path=/etc/hostname&username=root"
}
captures() { find "$CAPTURES" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l; }
sandbox_mounts() { grep -c "/container/sandboxes/" /proc/self/mountinfo; }
runtime_containers() { "$RUNTIME" --root "$RUNTIME_ROOT" list -q 2>/dev/null | grep -c '^aenv-'; }
fork_volumes() { call GET /volumes; jq '[.[]? // .volumes[]? | select(.name | startswith("volume-fork-"))] | length' <<<"$BODY_OUT"; }

: > "$LOG"

# --- 1. a failed capture leaves the source running ----------------------------
start_server "container-fork-seal"
create ""
A=$ID
start_counter "$A"
sleep 1
fork "$A" 2
check "a fork whose capture fails is refused (HTTP $STATUS)" test "$STATUS" != 201
grep -q "failpoint container-fork-seal triggered" "$LOG"
check "the failure came from the failpoint" test $? = 0
check "the source is running" test "$(state_of "$A")" = running
BEFORE=$(count_of "$A"); sleep 1; AFTER=$(count_of "$A")
check "its processes run again ($BEFORE -> $AFTER)" test "${AFTER:-0}" -gt "${BEFORE:-0}"
check "no capture left" test "$(captures)" = 0
call DELETE "/sandboxes/$A"
stop_server

# --- 2. one dump, three children ----------------------------------------------
start_server ""
call POST /volumes "{\"name\":\"$VOLUME\",\"sizeMB\":256}"
check "create volume" test "$STATUS" = 201
create ",\"volumeMounts\":[{\"name\":\"$VOLUME\",\"path\":\"/data\"}]"
check "create a secure sandbox with a volume" test -n "$TOKEN"
S=$ID; S_TOKEN=$TOKEN
in_box "$S" 'echo before > /root/marker && echo before > /data/v && sync' >/dev/null
start_counter "$S"
sleep 1
S_PID=$(counter_pid "$S")
S_COUNT=$(count_of "$S")
BASE_COPIES=$(fork_volumes)
fork "$S" 3
check "fork into three (HTTP $STATUS, ${FORK_MS} ms)" test "$STATUS" = 201 -a "${#KIDS[@]}" = 3
echo "      errors: $(jq -c '[arrays | .[] | .error // empty]' <<<"$BODY_OUT")"
check "the dump is gone once the fork returns" test "$(captures)" = 0
in_box "$S" 'echo after > /root/marker && echo after > /data/v && sync' >/dev/null
check "the source is running" test "$(state_of "$S")" = running
for i in 0 1 2; do
    K=${KIDS[$i]:-none}
    check "child $i is running" test "$(state_of "$K")" = running
    check "child $i runs the source's process (pid $S_PID)" test "$(counter_pid "$K")" = "$S_PID"
    C1=$(count_of "$K"); sleep 0.5; C2=$(count_of "$K")
    check "child $i counts on from the fork ($S_COUNT, then $C1 -> $C2)" \
        test "${C1:-0}" -ge "${S_COUNT:-1}" -a "${C2:-0}" -gt "${C1:-0}"
    check "child $i has the rootfs as forked" test "$(in_box "$K" 'cat /root/marker')" = before
    check "child $i has the volume as forked" test "$(in_box "$K" 'cat /data/v')" = before
    check "child $i has its own token" test -n "${KID_TOKENS[$i]:-}" -a "${KID_TOKENS[$i]:-}" != "$S_TOKEN"
    check "child $i's envd takes its own token" test "$(envd_accepts "$K" "${KID_TOKENS[$i]:-}")" = yes
    check "child $i's envd refuses the source's token" test "$(envd_accepts "$K" "$S_TOKEN")" = no
    check "child $i is reachable through the proxy with its own token" \
        test "$(envd_read "$K" "${KID_TOKENS[$i]:-}")" = 200
    check "the proxy refuses the source's token for child $i" test "$(envd_read "$K" "$S_TOKEN")" = 401
done
check "a child's envd refuses its sibling's token" \
    test "$(envd_accepts "${KIDS[0]:-none}" "${KID_TOKENS[1]:-}")" = no
check "the source's envd still takes its own token" test "$(envd_accepts "$S" "$S_TOKEN")" = yes
check "and refuses a child's" test "$(envd_accepts "$S" "${KID_TOKENS[0]:-}")" = no
in_box "${KIDS[0]:-none}" 'echo child0 > /root/marker && echo child0 > /data/v && sync' >/dev/null
check "a child's rootfs write stays out of its sibling" test "$(in_box "${KIDS[1]:-none}" 'cat /root/marker')" = before
check "a child's volume write stays out of its sibling" test "$(in_box "${KIDS[1]:-none}" 'cat /data/v')" = before
check "and out of the source" test "$(in_box "$S" 'cat /data/v')" = after
check "each child has its own volume copy" test "$(fork_volumes)" = $((BASE_COPIES + 3))
check "four runtime containers" test "$(runtime_containers)" = 4
# Volume reservations are not reconciled at startup: release them first.
for id in "$S" "${KIDS[@]}"; do call DELETE "/sandboxes/$id"; done
stop_server

# --- 3. one child fails to restore --------------------------------------------
start_server "container-restore*1"
create ",\"volumeMounts\":[{\"name\":\"$VOLUME\",\"path\":\"/data\"}]"
S=$ID
start_counter "$S"
sleep 1
S_PID=$(counter_pid "$S")
BASE_COPIES=$(fork_volumes)
fork "$S" 3
check "fork into three with one failing (HTTP $STATUS)" test "$STATUS" = 201
check "two children restored" test "${#KIDS[@]}" = 2
check "one child reports its restore error" test "$(jq '[arrays | .[] | select(.error)] | length' <<<"$BODY_OUT")" = 1
check "the failed child's volume copy is deleted ($(fork_volumes) vs $BASE_COPIES + 2)" \
    test "$(fork_volumes)" = $((BASE_COPIES + 2))
check "no capture left" test "$(captures)" = 0
check "three runtime containers" test "$(runtime_containers)" = 3

# --- 4. children outlive their source -------------------------------------------
call DELETE "/sandboxes/$S"
check "delete the source (HTTP $STATUS)" test "$STATUS" = 204
for K in "${KIDS[@]}"; do
    check "child $K still runs the source's process (pid $S_PID)" \
        test -n "$S_PID" -a "$(counter_pid "$K")" = "$S_PID"
    C1=$(count_of "$K"); sleep 0.5; C2=$(count_of "$K")
    check "and it keeps counting ($C1 -> $C2)" test "${C2:-0}" -gt "${C1:-0}"
    call DELETE "/sandboxes/$K"
    check "delete child $K (HTTP $STATUS)" test "$STATUS" = 204
done
check "no runtime containers left" test "$(runtime_containers)" = 0
check "no sandbox mounts left" test "$(sandbox_mounts)" = 0
check "no sealed layers left" test "$(find "$AENV_HOME_PATH/container/layers" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)" = 0
stop_server

echo
if [ "$FAILURES" -eq 0 ]; then echo "full fork: all checks passed"; else echo "full fork: $FAILURES check(s) failed"; exit 1; fi
