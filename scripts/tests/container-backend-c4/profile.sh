#!/bin/bash
# Records the processes and syscalls behind one container sandbox lifecycle:
# create (cached image), one exec, delete. Run as root in the dev container.
set -uo pipefail
BASE=/src/scripts/tests/container-backend-c0/c0.toml
PORT=18000; API=http://127.0.0.1:$PORT
IMAGE=${PROFILE_IMAGE:-docker.io/library/ubuntu:22.04}
# Output always lands in its own directory under /state/profile, which is
# the only place the script deletes from.
NAME=${PROFILE_NAME:-default}
case "$NAME" in ''|*/*|.*) echo "PROFILE_NAME must be a plain name" >&2; exit 2;; esac
OUT=/state/profile/$NAME
mkdir -p "$OUT" /run/yzd-aenv-ct
rm -f -- "$OUT/trace" "$OUT/trace".* "$OUT/marks" "$OUT/server.log"
sed 's/^enabled_backends = .*/enabled_backends = ["container"]/' "$BASE" > /tmp/prof.toml
if [ -n "${PROFILE_RUNTIME:-}" ]; then printf '\n[container]\nruntime = "%s"\n' "$PROFILE_RUNTIME" >> /tmp/prof.toml; fi
AENV_CONFIG_PATH=/tmp/prof.toml API_ADDR=127.0.0.1:$PORT /target/debug/server > "$OUT/server.log" 2>&1 &
SERVER=$!
for _ in $(seq 1 240); do curl -sf -o /dev/null "$API/health" && break; sleep 0.5; done
KEY=$(cat "$AENV_HOME_PATH/secrets/api-key")
printf 'url = "%s"\napi_key = "%s"\n' "$API" "$KEY" > /root/.config/aenv/credentials
die() { echo "profile: $*" >&2; kill -TERM "$SERVER" 2>/dev/null; exit 1; }
# call METHOD PATH [BODY]: prints the body; fails on a non-2xx status.
call() {
    local body status
    body=$(curl -s -w '\n%{http_code}' -X "$1" "$API$2" -H "X-API-Key: $KEY" \
        -H 'Content-Type: application/json' ${3:+-d "$3"}) || die "$1 $2: request failed"
    status=${body##*$'\n'}
    body=${body%$'\n'*}
    case "$status" in 2??) printf '%s' "$body";; *) die "$1 $2: HTTP $status: $body";; esac
}
create() {
    local id
    id=$(call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\"}" | jq -r .sandboxID)
    [ -n "$id" ] && [ "$id" != null ] || die "create returned no sandboxID"
    printf '%s' "$id"
}
# Warm the image and the slot pool once, untraced.
ID=$(create) || exit 1
call DELETE "/sandboxes/$ID" >/dev/null || exit 1
sleep 3

strace -f -qq -ttt -T -e trace=execve,mount,umount2,setns,unshare,clone,clone3,ioctl,sendmsg,connect \
    -o "$OUT/trace" -p "$SERVER" &
TRACER=$!
sleep 1
mark() { echo "$(date +%s.%N) $1" >> "$OUT/marks"; }
mark create-start
ID=$(create) || { kill -INT "$TRACER"; exit 1; }
mark create-end
/target/debug/aenv exec "$ID" -- true >/dev/null 2>&1 || echo "profile: exec failed" >&2
mark exec-end
call DELETE "/sandboxes/$ID" >/dev/null || { kill -INT "$TRACER"; exit 1; }
mark delete-end
sleep 1
kill -INT "$TRACER"; wait "$TRACER" 2>/dev/null
kill -TERM "$SERVER"; wait "$SERVER" 2>/dev/null
echo "trace: $(wc -l < "$OUT/trace") lines in $OUT/trace"
cat "$OUT/marks"
