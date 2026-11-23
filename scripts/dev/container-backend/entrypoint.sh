#!/bin/bash
# Move PID 1 into a leaf cgroup so nested runc containers can create child
# cgroups (cgroup v2 "no internal processes" rule), then enable controllers.
set -e
if [ -w /sys/fs/cgroup/cgroup.subtree_control ]; then
  mkdir -p /sys/fs/cgroup/init
  for p in $(cat /sys/fs/cgroup/cgroup.procs); do echo "$p" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true; done
  for c in $(cat /sys/fs/cgroup/cgroup.controllers); do echo "+$c" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true; done
fi
exec "$@"
