#!/bin/bash
# Manage the container-backend dev container on a shared host (no sudo).
# Heavy data lives on / under /var/tmp; source stays in the /home worktree.
set -euo pipefail
NAME=yzd-aenv-ct-dev
IMAGE=yzd-aenv-ct-dev:latest
SRC=/home/i_yinzida/AgentENV-ct
DATA=/var/tmp/i_yinzida/aenv-ct
HERE=$(cd "$(dirname "$0")" && pwd)

case "${1:-}" in
  build) docker build -t "$IMAGE" "$HERE" ;;
  up)
    mkdir -p "$DATA"/{target,cargo,state}
    docker run -d --name "$NAME" --hostname "$NAME" \
      --privileged --cgroupns=private --init \
      -v /dev:/dev \
      -v "$SRC":/src \
      -v "$DATA/target":/target \
      -v "$DATA/cargo":/cargo \
      -v "$DATA/state":/state \
      -e AENV_HOME_PATH=/state/home \
      -e AENV_RUNTIME_PATH=/run/yzd-aenv-ct \
      -w /src "$IMAGE" ;;
  sh)   docker exec -it -u developer "$NAME" bash ;;        # build/test as uid 1052
  root) docker exec -it "$NAME" bash ;;                    # runtime experiments
  down) docker rm -f "$NAME" ;;
  *) echo "usage: $0 build|up|sh|root|down" >&2; exit 2 ;;
esac
