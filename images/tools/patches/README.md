# envd patches

The tools image applies these to the envd source (`ENVD_REF`) before
building it, in name order. Each must apply cleanly to that ref; refresh
them when `ENVD_REF` moves.

## 0001-envd-access-token-hash-file.patch

With `-isnotfc`, envd normally accepts an `/init` token only if it matches
the token envd already holds. Firecracker lets the orchestrator authorize a
different token by putting its hash in MMDS; containers have no MMDS.

With this patch, envd under `-isnotfc` reads that hash from
`/run/agentenv/access-token-hash` (the SHA-512 of the token, hex encoded).
The container backend binds that path read-only into every container, from
the sandbox's `auth/` work directory. It writes the file for every sandbox
restored under a new identity (a full-fork child, or a launch from a
memory snapshot). The restored envd still holds its source's token, and the
file lets `/init` switch it to the new sandbox's own token. For a
non-secure sandbox, the file holds the hash of the empty token, which lets
`/init` clear it.

A switch (or clear) the file authorizes is applied even if the request's timestamp is
older than the last one envd accepted. A restored envd keeps its source's
`lastSetTime`, so otherwise a clock that went back would make `/init` skip the
switch and still answer 204.

If the file is missing or empty, the behaviour is the same as upstream.

The build lists the applied patches, by file name without `.patch`, in
`/agentenv/envd-patches`. The container backend refuses a secure full fork
when this one is missing from that list.
Firecracker guests (no `-isnotfc`) are unaffected.
