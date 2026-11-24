# Dev image for the container backend. Built on the local agentenv-dev image
# (Debian trixie, Rust in /opt/rust, protoc/clang already installed).
FROM agentenv-dev:local
USER root
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      runc crun iptables iproute2 e2fsprogs util-linux kmod jq busybox-static \
      uidmap strace psmisc curl ca-certificates \
      nodejs npm default-jre-headless umoci zstd \
 && rm -rf /var/lib/apt/lists/*
# Go toolchain for services/ (gateway, scheduler) and the exact code
# generators upstream used for services/api/proto.
ARG GO_VERSION=1.25.9
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xz \
 && GOBIN=/usr/local/bin /usr/local/go/bin/go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11 \
 && GOBIN=/usr/local/bin /usr/local/go/bin/go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2 \
 && rm -rf /root/go /root/.cache
ENV PATH=/usr/local/go/bin:/opt/rust/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    GOPATH=/cargo/go GOCACHE=/cargo/go-build GOFLAGS=-modcacherw
# overlaybd-apply validates its built-in default config path (see deploy/docker/Dockerfile.agentenv).
RUN mkdir -p /etc/overlaybd && printf '{}\n' > /etc/overlaybd/overlaybd.json
COPY entrypoint.sh /usr/local/bin/aenv-ct-entrypoint
RUN chmod 0755 /usr/local/bin/aenv-ct-entrypoint
ENV CARGO_HOME=/cargo CARGO_TARGET_DIR=/target
ENTRYPOINT ["/usr/local/bin/aenv-ct-entrypoint"]
CMD ["sleep", "infinity"]
