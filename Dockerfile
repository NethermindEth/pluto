FROM rust:1.95.0-bookworm AS builder

ARG GIT_COMMIT_HASH_SHORT
ENV GIT_COMMIT_HASH_SHORT=${GIT_COMMIT_HASH_SHORT}

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

RUN apt-get update && \
  apt-get install -y pkg-config \
  openssl libssl-dev \
  protobuf-compiler=3.21.12*

WORKDIR /build
COPY rust-toolchain.toml .
RUN rustup show

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install oas3-gen@0.24.0

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --locked --release --package pluto-cli && \
    cp /build/target/release/pluto /usr/local/bin/pluto

# Staging directory for the runtime working directory; the distroless final
# stage has no shell, so it is created here and copied over with --chown.
RUN mkdir -p /rootfs/opt/charon

FROM gcr.io/distroless/cc-debian13 AS app

COPY --from=builder /usr/local/bin/pluto /usr/local/bin/pluto

# Match charon's working directory so that relative paths passed to flags such
# as `--split-keys-dir` / `--cluster-dir` resolve under /opt/charon, keeping
# pluto a drop-in replacement for charon.
COPY --from=builder --chown=1000:1000 /rootfs/opt/charon /opt/charon
WORKDIR /opt/charon

# Match charon's non-root user (uid/gid 1000) so files written to mounted
# volumes have the same ownership regardless of which client wrote them.
USER 1000:1000
ENV HOME=/opt/charon

ENTRYPOINT ["/usr/local/bin/pluto"]
# Match charon's default command so that setups relying on the image's
# default (no explicit command/args) start the validator client.
CMD ["run"]

# Used by GitHub to associate container with repo.
LABEL org.opencontainers.image.source="https://github.com/NethermindEth/pluto"
LABEL org.opencontainers.image.title="pluto"
LABEL org.opencontainers.image.description="Proof of Stake Ethereum Distributed Validator Client"
LABEL org.opencontainers.image.licenses="BUSL-1.1"
LABEL org.opencontainers.image.documentation="https://docs.obol.org/"
