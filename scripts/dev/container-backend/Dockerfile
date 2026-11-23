# Dev image for the container backend. Built on the local agentenv-dev image
# (Debian trixie, Rust in /opt/rust, protoc/clang already installed).
FROM agentenv-dev:local
USER root
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      runc crun iptables iproute2 e2fsprogs util-linux kmod jq busybox-static \
      uidmap strace psmisc curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# overlaybd-apply validates its built-in default config path (see deploy/docker/Dockerfile.agentenv).
RUN mkdir -p /etc/overlaybd && printf '{}\n' > /etc/overlaybd/overlaybd.json
COPY entrypoint.sh /usr/local/bin/aenv-ct-entrypoint
RUN chmod 0755 /usr/local/bin/aenv-ct-entrypoint
ENV CARGO_HOME=/cargo CARGO_TARGET_DIR=/target
ENTRYPOINT ["/usr/local/bin/aenv-ct-entrypoint"]
CMD ["sleep", "infinity"]
