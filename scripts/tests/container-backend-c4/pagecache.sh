#!/bin/bash
# Measures page cache duplication: N containers from one image each read
# /usr; compares the page cache charged to each container's cgroup.
set -uo pipefail
N=${N:-3}
BASE=/src/scripts/tests/container-backend-c0/c0.toml
PORT=18000; API=http://127.0.0.1:$PORT
IMAGE=${PROFILE_IMAGE:-docker.io/library/ubuntu:22.04}
mkdir -p /run/yzd-aenv-ct
sed 's/^enabled_backends = .*/enabled_backends = ["container"]/' "$BASE" > /tmp/pc.toml
AENV_CONFIG_PATH=/tmp/pc.toml API_ADDR=127.0.0.1:$PORT /target/debug/server > /state/pagecache-server.log 2>&1 &
SERVER=$!
trap 'kill -TERM $SERVER; wait $SERVER 2>/dev/null' EXIT
for _ in $(seq 1 240); do curl -sf -o /dev/null "$API/health" && break; sleep 0.5; done
KEY=$(cat "$AENV_HOME_PATH/secrets/api-key")
printf 'url = "%s"\napi_key = "%s"\n' "$API" "$KEY" > /root/.config/aenv/credentials
call() { curl -s -X "$1" "$API$2" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' ${3:+-d "$3"}; }
file_mib() { awk '/^file /{printf "%.1f", $2/1048576}' "/sys/fs/cgroup/aenv-container/aenv-$1/memory.stat"; }
IDS=()
BYTES=0
for i in $(seq 1 "$N"); do
    ID=$(call POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\",\"memoryMB\":2048,\"timeout\":300}" | jq -r .sandboxID)
    IDS+=("$ID")
    BEFORE=$(file_mib "$ID")
    BYTES=$(/target/debug/aenv exec "$ID" -- sh -c 'tar cf - /usr 2>/dev/null | wc -c' 2>/dev/null)
    echo "container $i: read $((BYTES / 1048576)) MiB of /usr; page cache charged: $BEFORE -> $(file_mib "$ID") MiB"
done
echo "host Cached: $(awk '/^Cached:/{printf "%.0f MiB", $2/1024}' /proc/meminfo)"
for ID in "${IDS[@]}"; do call DELETE "/sandboxes/$ID" >/dev/null; done
