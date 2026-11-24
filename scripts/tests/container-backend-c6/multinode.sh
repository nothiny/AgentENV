#!/bin/bash
# C6 end-to-end test: backend-aware scheduling across two nodes.
#
#   scheduler (static discovery) <- heartbeats -- node-ct: the real server,
#   gateway  -> scheduler                          container backend only
#                                               -- node-fc: stubnode that
#                                                  reports firecracker only
#
# Creates through the gateway must land on a node that runs the requested
# backend, and a backend no node runs is refused with 400.
# Run as root inside the dev container after building the server, ublk
# daemon and CLI (see the C2 smoke test):
#   docker exec yzd-aenv-ct-dev bash /src/scripts/tests/container-backend-c6/multinode.sh
set -uo pipefail

BASE=/src/scripts/tests/container-backend-c0/c0.toml
SERVER=/target/debug/server
GOBIN=/target/go-bin
IMAGE=${C6_IMAGE:-docker.io/library/ubuntu:22.04}
NODE_PORT=18000
STUB_PORT=18010
GATEWAY_PORT=18080
SCHED_PORT=19090
NODE=http://127.0.0.1:$NODE_PORT
GATEWAY=http://127.0.0.1:$GATEWAY_PORT
LOGDIR=/state/c6
FAILURES=0
PIDS=()

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }
check() { local label=$1; shift; if "$@"; then pass "$label"; else fail "$label"; fi; }
cleanup() {
    for pid in "${PIDS[@]}"; do kill -TERM "$pid" 2>/dev/null; done
    for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null; done
}
trap cleanup EXIT
wait_for() { # url label
    for _ in $(seq 1 240); do curl -sf -o /dev/null "$1" && return 0; sleep 0.5; done
    echo "$2 did not come up; see $LOGDIR"; exit 1
}

mkdir -p "$LOGDIR" "$GOBIN" /run/yzd-aenv-ct
rm -f -- "$LOGDIR"/*.log
for bin in scheduler:./scheduler/cmd gateway:./gateway/cmd stubnode:./scheduler/e2e/stubnode; do
    (cd /src/services && go build -o "$GOBIN/${bin%%:*}" "${bin#*:}") || { echo "go build ${bin%%:*} failed"; exit 1; }
done

cat > /tmp/c6-services.json <<EOF
{
  "log_level": "info",
  "scheduler": {
    "grpc_listen_addr": "127.0.0.1:$SCHED_PORT",
    "metrics_listen_addr": "127.0.0.1:19091",
    "strategy": "round_robin",
    "report_ttl": "15s",
    "binding_ttl": "60s",
    "discovery": {"mode": "static"},
    "nodes": [
      {"id": "node-ct", "endpoint": "$NODE"},
      {"id": "node-fc", "endpoint": "http://127.0.0.1:$STUB_PORT"}
    ]
  },
  "gateway": {
    "http_listen_addr": "127.0.0.1:$GATEWAY_PORT",
    "metrics_listen_addr": "127.0.0.1:18081",
    "scheduler_addr": "127.0.0.1:$SCHED_PORT",
    "tls": {"mode": "off"}
  }
}
EOF

# --- start the scheduler, the real node, the stub and the gateway ---------------
"$GOBIN/scheduler" -config /tmp/c6-services.json > "$LOGDIR/scheduler.log" 2>&1 &
PIDS+=($!)

sed -e 's/^enabled_backends = .*/enabled_backends = ["container"]/' \
    -e 's|^# scheduler_endpoint = .*|scheduler_endpoint = "http://127.0.0.1:'$SCHED_PORT'"|' \
    -e 's/^node_id = .*/node_id = "node-ct"/' "$BASE" > /tmp/c6.toml
# Turn on the scheduler report (the first `enabled` after its section).
awk '/^\[observability.scheduler_report\]/{s=1} s&&/^enabled = /{sub(/false/,"true");s=0} {print}' \
    /tmp/c6.toml > /tmp/c6.toml.new && mv /tmp/c6.toml.new /tmp/c6.toml
grep -q '^scheduler_endpoint' /tmp/c6.toml || { echo "c6.toml: scheduler_endpoint not set"; exit 1; }
AENV_CONFIG_PATH=/tmp/c6.toml API_ADDR=127.0.0.1:$NODE_PORT "$SERVER" > "$LOGDIR/node-ct.log" 2>&1 &
PIDS+=($!)
wait_for "$NODE/health" "node-ct"
KEY=$(cat "$AENV_HOME_PATH/secrets/api-key")

"$GOBIN/stubnode" -id node-fc -listen 127.0.0.1:$STUB_PORT -scheduler 127.0.0.1:$SCHED_PORT \
    -cluster-id 00000000-0000-0000-0000-000000000000 -interval 2s \
    -sandbox-backends firecracker > "$LOGDIR/node-fc.log" 2>&1 &
PIDS+=($!)

AENV_API_KEY=$KEY "$GOBIN/gateway" -config /tmp/c6-services.json > "$LOGDIR/gateway.log" 2>&1 &
PIDS+=($!)
wait_for "$GATEWAY/health" "gateway"

call() { # base method path [body]
    local out
    out=$(curl -s -w '\n%{http_code}' -X "$2" "$1$3" -H "X-API-Key: $KEY" \
        -H 'Content-Type: application/json' ${4:+-d "$4"})
    STATUS=${out##*$'\n'}
    BODY_OUT=${out%$'\n'*}
}
backends_of() { # node-id
    call "$GATEWAY" GET /nodes
    jq -r --arg id "$1" '[.[] | select(.id == $id)][0].sandboxBackends // [] | join(",")' <<<"$BODY_OUT" 2>/dev/null
}

# Both nodes report their backends.
for _ in $(seq 1 60); do
    [ "$(backends_of node-ct)" = container ] && [ "$(backends_of node-fc)" = firecracker ] && break
    sleep 1
done
check "gateway lists node-ct with the container backend" test "$(backends_of node-ct)" = container
check "gateway lists node-fc with the firecracker backend" test "$(backends_of node-fc)" = firecracker

# --- placement ------------------------------------------------------------------
created_on_ct=0
CT_IDS=()
for i in 1 2 3; do
    call "$GATEWAY" POST /sandboxes-cold "{\"image\":\"$IMAGE\",\"backend\":\"container\",\"timeout\":300}"
    ID=$(jq -r .sandboxID <<<"$BODY_OUT")
    if [ "$STATUS" = 201 ] && [ "${ID#stub-}" = "$ID" ]; then
        CT_IDS+=("$ID")
        call "$NODE" GET "/sandboxes/$ID"
        [ "$STATUS" = 200 ] && created_on_ct=$((created_on_ct + 1))
    else
        echo "      container create $i: HTTP $STATUS $BODY_OUT"
    fi
done
check "every container create lands on node-ct ($created_on_ct/3)" test "$created_on_ct" = 3

ON_FC=0
for body in '{"image":"x","backend":"firecracker"}' '{"image":"x"}' '{"templateID":"base"}'; do
    case "$body" in *templateID*) path=/sandboxes;; *) path=/sandboxes-cold;; esac
    for _ in 1 2; do
        call "$GATEWAY" POST "$path" "$body"
        [ "$STATUS" = 201 ] && [ "$(jq -r .nodeID <<<"$BODY_OUT")" = node-fc ] && ON_FC=$((ON_FC + 1))
    done
done
check "firecracker, default and template creates land on node-fc ($ON_FC/6)" test "$ON_FC" = 6

call "$GATEWAY" POST /sandboxes-cold '{"image":"x","backend":"qemu"}'
check "a backend no node runs is refused (HTTP $STATUS)" test "$STATUS" = 400

# --- requests for existing sandboxes follow their node ----------------------------
if [ "${#CT_IDS[@]}" -gt 0 ]; then
    call "$GATEWAY" GET "/sandboxes/${CT_IDS[0]}"
    check "gateway routes a container sandbox's reads to node-ct" test "$STATUS" = 200
    call "$GATEWAY" POST "/sandboxes/${CT_IDS[0]}/images" '{"name":"c6-image"}'
    check "and its image publish" test "$STATUS" = 201
fi
for id in "${CT_IDS[@]}"; do
    call "$GATEWAY" DELETE "/sandboxes/$id"
    check "delete $id through the gateway" test "$STATUS" = 204
done

echo
if [ "$FAILURES" -eq 0 ]; then echo "C6 multi-node: all checks passed"; else echo "C6 multi-node: $FAILURES check(s) failed; logs in $LOGDIR"; exit 1; fi
