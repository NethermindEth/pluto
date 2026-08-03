# syntax=docker/dockerfile:1

# Digest pinned 2026-08-03.
FROM rust:slim-bookworm@sha256:99e09cb2284e2ddbb73a995deee3e91783fd04d177602ccf6eab326d778ee777 AS chef

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    protobuf-compiler=3.21.12-3 && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN cargo install cargo-chef --locked --version 0.1.77

WORKDIR /build

# `rustup show` installs the toolchain pinned in rust-toolchain.toml.
COPY rust-toolchain.toml .
RUN rustup show

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

RUN cargo install oas3-gen --locked --version 0.24.0

# No cache mounts: compiled deps must live in image layers for CI's `cache-to: type=gha` to persist them (gha stores layers, not mounts).
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --locked --release --package pluto-cli --recipe-path recipe.json

# These change every commit; declared after the cook step so they don't invalidate the dependency layer above.
ARG GIT_COMMIT_HASH_SHORT
ENV GIT_COMMIT_HASH_SHORT=${GIT_COMMIT_HASH_SHORT}

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

COPY . .
# `rm -rf target` keeps this per-commit layer at ~binary size in the gha cache.
RUN cargo build --locked --release --package pluto-cli && \
    cp /build/target/release/pluto /usr/local/bin/pluto && \
    rm -rf /build/target

# Digest pinned 2026-08-03.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    fio \
    wget && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=builder /usr/local/bin/pluto /app/bin/pluto

ENTRYPOINT ["/app/bin/pluto"]
# Default to `run` command
CMD ["run"]

# Image metadata
LABEL org.opencontainers.image.source="https://github.com/NethermindEth/pluto"
LABEL org.opencontainers.image.title="pluto"
LABEL org.opencontainers.image.description="Proof of Stake Ethereum Distributed Validator Client"
LABEL org.opencontainers.image.licenses="BUSL-1.1"
LABEL org.opencontainers.image.documentation="https://docs.obol.org/"
