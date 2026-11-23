# Container backend C0 spike

Proves that a sandbox can run as an OCI container on the same OverlayBD/ublk
rootfs Firecracker uses, in a slot-shaped netns where a veth pair replaces
`tap0`, with the tools-drive envd (`-isnotfc`) as the guest agent.

- Code: `src/sandbox/container_c0.rs` (`#[cfg(test)]`, `#[ignore]`).
- Config: `c0.toml` = `config/default.toml` plus:
  - a unique ublk daemon socket (`/run/yzd-aenv-ct/ublk-daemon.sock`). This is
    required on a shared host: the daemon's owner tag is a hash of the socket
    path, and its startup sweep deletes unused devices carrying the same tag.
  - metrics endpoint off;
  - block pool off, so cleanup deletes devices instead of pooling them.

## Run (inside the dev container, see `scripts/dev/container-backend`)

```bash
# once: download deps and convert the tools image
docker exec -e AENV_CONFIG_PATH=/src/scripts/tests/container-backend-c0/c0.toml \
  yzd-aenv-ct-dev bash -c "mkdir -p /run/yzd-aenv-ct && cd /state && /target/debug/server --setup-only"

# build the test binary as uid 1052 ...
docker exec -u developer -w /src yzd-aenv-ct-dev cargo test -p agentenv --lib --no-run container_c0

# ... and run it as root (optional: -e C0_RUNTIME=crun, -e C0_IMAGE=<ref>)
docker exec -e AENV_CONFIG_PATH=/src/scripts/tests/container-backend-c0/c0.toml -w /state \
  yzd-aenv-ct-dev /target/debug/deps/agentenv-<hash> sandbox::container_c0 --ignored --nocapture
```

## Result (2026-11-23, yzd_106, kernel 6.8, `ubuntu:22.04`)

PASS with runc 1.1.15 and crun 1.21:

- exec, env vars from `/init`, file write/read, image `os-release`
- cgroup limits applied (memory 2 GiB, pids 4096, cpu 2)
- outbound HTTP through the slot SNAT + dev-container MASQUERADE
- wrong access token rejected
- envd did not set the clock ("within acceptable range"); no MMDS polling
- cleanup leaves no mounts, netns, veths, runc state or ublk devices

| phase | runc | crun |
|---|---|---|
| tools + rootfs ublk devices | 21 ms | 21 ms |
| mount rootfs + tools | 11-45 ms | 7 ms |
| network (ip CLI, no pool) | 173-234 ms | 168 ms |
| runtime create | 85-92 ms | 63 ms |
| runtime start | 5-7 ms | 4 ms |
| envd health + init | 5 ms | 5 ms |
| first exec | 10 ms | 16 ms |
| container `memory.current`, idle envd | 24 MiB | 23 MiB |

Image resolve: 16 s on first pull, ~3.7 s when cached (registry manifest
check). Excluding image resolve and network setup (pooled in production), a
container is ready in about 150 ms.

## Findings to carry into C2

1. **Reaping.** After `runc create` exits, the container init is reparented to
   the nearest subreaper. The server must set `PR_SET_CHILD_SUBREAPER` (or run a
   per-container monitor) and reap. The dev container now runs with `--init`;
   before that, killed containers left `[envd] <defunct>` zombies.
2. envd runs fine as PID 1 with `-isnotfc`. Reaping of orphaned grandchildren
   inside the container by envd is not tested yet.
3. Each command makes envd log "Trying to access secured envd without correct
   access token" once, although the command succeeds. Check whether a
   follow-up request is sent without the token (and whether Firecracker shows
   the same).
4. Default rootfs virtual size is 64 GiB; `diskSizeMB` maps to
   `requested_virtual_size`.
5. Network setup via the `ip` CLI costs 170-230 ms. Reuse `NetworkManager`
   slots (warm pool, netlink) and add only the veth.
6. The empty parent cgroup `/aenv-ct` remains after cleanup; harmless.
